# Cloud Network Security Reference

A comprehensive reference for network security controls across AWS, Azure, and GCP — covering architecture, firewall policy, WAF configuration, private connectivity, DDoS protection, flow log analysis, and compliance mappings.

---

## Table of Contents

- [AWS Network Security](#aws-network-security)
  - [VPC Architecture](#vpc-architecture)
  - [Security Groups](#security-groups)
  - [Network ACLs](#network-acls-nacls)
  - [AWS Network Firewall](#aws-network-firewall)
  - [VPC Flow Logs](#vpc-flow-logs)
  - [AWS WAF v2](#aws-waf-v2)
  - [GuardDuty Network Findings](#guardduty-network-findings)
  - [AWS PrivateLink](#aws-privatelink)
- [Azure Network Security](#azure-network-security)
  - [VNet and NSG](#vnet-and-nsg)
  - [Azure Firewall Premium](#azure-firewall-premium)
  - [Azure Private Endpoints](#azure-private-endpoints)
  - [Azure DDoS Protection Standard](#azure-ddos-protection-standard)
  - [Azure Front Door and WAF](#azure-front-door-and-waf)
- [GCP Network Security](#gcp-network-security)
  - [Custom Mode VPC](#custom-mode-vpc)
  - [Cloud Armor](#cloud-armor)
  - [VPC Service Controls](#vpc-service-controls)
  - [GCP VPC Flow Logs](#gcp-vpc-flow-logs)
- [Cross-Cloud Comparison](#cross-cloud-comparison)
- [Compliance Mappings](#compliance-mappings)

---

## AWS Network Security

### VPC Architecture

An Amazon VPC (Virtual Private Cloud) is the foundational network isolation boundary in AWS. Every VPC is defined by one or more CIDR blocks and spans all Availability Zones in a region. Subnets are always scoped to a single AZ.

**Recommended four-tier subnet design per AZ:**

| Tier | Subnet Name | Example CIDR (/VPC 10.0.0.0/16) | Route Table |
|---|---|---|---|
| Public | public-az1 | 10.0.0.0/24 | IGW default route |
| Private App | private-app-az1 | 10.0.10.0/24 | NAT Gateway default route |
| Private Data | private-data-az1 | 10.0.20.0/24 | Local only (no internet route) |
| Intra (isolated) | intra-az1 | 10.0.30.0/24 | Local only, VPC Endpoints only |

**Internet Gateway (IGW)** — Attached to the VPC; provides bidirectional internet access for public subnets. One per VPC.

**NAT Gateway** — Allows private subnets to initiate outbound internet connections; deployed in a public subnet. Use one per AZ for HA.

```bash
# Create a VPC
aws ec2 create-vpc --cidr-block 10.0.0.0/16 --tag-specifications \
  'ResourceType=vpc,Tags=[{Key=Name,Value=prod-vpc}]'

# Enable DNS hostnames (required for PrivateLink and some services)
aws ec2 modify-vpc-attribute --vpc-id vpc-0abc123 --enable-dns-hostnames

# Create public subnet
aws ec2 create-subnet --vpc-id vpc-0abc123 \
  --cidr-block 10.0.0.0/24 \
  --availability-zone us-east-1a \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=public-az1}]'

# Create NAT Gateway (requires an EIP)
aws ec2 allocate-address --domain vpc
aws ec2 create-nat-gateway --subnet-id subnet-0pub123 --allocation-id eipalloc-0abc
```

**VPC Endpoints** reduce exposure by keeping traffic off the public internet:

| Type | Traffic Path | Use Case |
|---|---|---|
| Gateway Endpoint | Route table entry | S3, DynamoDB (free) |
| Interface Endpoint (PrivateLink) | ENI in your subnet | Most other AWS services |

```bash
# Create S3 Gateway Endpoint
aws ec2 create-vpc-endpoint \
  --vpc-id vpc-0abc123 \
  --service-name com.amazonaws.us-east-1.s3 \
  --route-table-ids rtb-0abc123

# Create Interface Endpoint for Secrets Manager
aws ec2 create-vpc-endpoint \
  --vpc-id vpc-0abc123 \
  --vpc-endpoint-type Interface \
  --service-name com.amazonaws.us-east-1.secretsmanager \
  --subnet-ids subnet-0priv123 \
  --security-group-ids sg-0abc123 \
  --private-dns-enabled
```

---

### Security Groups

Security Groups are **stateful**, virtual firewalls applied at the ENI level. Return traffic is automatically allowed regardless of outbound rules. Unlike NACLs, Security Groups support **SG-to-SG references** — this is the preferred pattern for intra-VPC rules because it avoids hardcoding CIDR blocks that change as instances scale.

**Three-tier Security Group design (Terraform):**

```hcl
# ALB Security Group — accepts HTTPS from the internet
resource "aws_security_group" "alb" {
  name   = "alb-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# App Security Group — accepts traffic only from ALB SG
resource "aws_security_group" "app" {
  name   = "app-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]  # SG reference, not CIDR
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# DB Security Group — accepts traffic only from App SG
resource "aws_security_group" "db" {
  name   = "db-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

**Security Group best practices:**

- Never allow `0.0.0.0/0` on port 22 (SSH) or 3389 (RDP). Use AWS Systems Manager Session Manager for shell access — no inbound ports required.
- Apply the principle of least privilege: use the minimum port range, never `0-65535`.
- Use SG references for all intra-VPC service-to-service rules.
- Tag security groups with owner, service, and environment.
- Regularly audit with AWS Config rules.

**AWS Config rules for Security Group compliance:**

| Config Rule | What It Checks |
|---|---|
| `restricted-ssh` | Flags SGs allowing SSH (port 22) from 0.0.0.0/0 or ::/0 |
| `restricted-common-ports` | Flags unrestricted access on ports 20, 21, 3389, 3306, 4333 |
| `vpc-sg-open-only-to-authorized-ports` | Custom — specify allowed inbound ports |
| `vpc-default-security-group-closed` | Default SG should have no rules |

```bash
# Check for Security Groups with unrestricted SSH
aws ec2 describe-security-groups \
  --filters "Name=ip-permission.from-port,Values=22" \
            "Name=ip-permission.cidr,Values=0.0.0.0/0" \
  --query 'SecurityGroups[*].[GroupId,GroupName]' \
  --output table

# Enable AWS Config rule
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "restricted-ssh",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "INCOMING_SSH_DISABLED"
  }
}'
```

---

### Network ACLs (NACLs)

Network ACLs are **stateless** — you must explicitly allow both inbound and return (outbound) traffic. Rules are processed in ascending numeric order; the first match wins. NACLs are applied at the subnet boundary, not the instance level.

**Key differences from Security Groups:**

| Feature | Security Group | Network ACL |
|---|---|---|
| Statefulness | Stateful | Stateless |
| Scope | ENI (instance) | Subnet |
| Rule direction | Inbound + outbound | Inbound + outbound (both required) |
| Explicit deny | No (implicit deny) | Yes |
| Rule ordering | All rules evaluated | First match wins (numbered) |
| Best for | Instance-level micro-segmentation | Subnet-level coarse blocking |

**Example NACL for a private app subnet:**

```bash
# Create a NACL
aws ec2 create-network-acl --vpc-id vpc-0abc123 \
  --tag-specifications 'ResourceType=network-acl,Tags=[{Key=Name,Value=private-app-nacl}]'

# Inbound: allow HTTPS from ALB subnet CIDR
aws ec2 create-network-acl-entry \
  --network-acl-id acl-0abc123 \
  --ingress \
  --rule-number 100 \
  --protocol tcp \
  --port-range From=8080,To=8080 \
  --cidr-block 10.0.0.0/24 \
  --rule-action allow

# Inbound: allow ephemeral return ports (responses from internet via NAT)
aws ec2 create-network-acl-entry \
  --network-acl-id acl-0abc123 \
  --ingress \
  --rule-number 200 \
  --protocol tcp \
  --port-range From=1024,To=65535 \
  --cidr-block 0.0.0.0/0 \
  --rule-action allow

# Inbound: explicit deny all
aws ec2 create-network-acl-entry \
  --network-acl-id acl-0abc123 \
  --ingress \
  --rule-number 32766 \
  --protocol -1 \
  --cidr-block 0.0.0.0/0 \
  --rule-action deny

# Outbound: allow app to reach DB subnet
aws ec2 create-network-acl-entry \
  --network-acl-id acl-0abc123 \
  --egress \
  --rule-number 100 \
  --protocol tcp \
  --port-range From=5432,To=5432 \
  --cidr-block 10.0.20.0/24 \
  --rule-action allow

# Outbound: allow ephemeral return ports (responses to ALB)
aws ec2 create-network-acl-entry \
  --network-acl-id acl-0abc123 \
  --egress \
  --rule-number 200 \
  --protocol tcp \
  --port-range From=1024,To=65535 \
  --cidr-block 10.0.0.0/24 \
  --rule-action allow
```

**When to use NACLs vs Security Groups:**
- Use NACLs to **explicitly deny** known-bad IPs or CIDR ranges at the subnet boundary.
- Use NACLs to enforce a hard perimeter between tiers (e.g., deny all traffic from the public subnet to the data tier).
- Use Security Groups for all service-to-service allow rules.

---

### AWS Network Firewall

AWS Network Firewall is a managed stateful firewall service deployed inline in a dedicated firewall subnet. It supports both **stateless** (fast path, 5-tuple matching) and **stateful** (deep packet inspection, Suricata-compatible) rule groups.

**Architecture:**
1. Create a firewall subnet in each AZ (dedicated `/28` recommended).
2. Deploy the firewall in each subnet.
3. Update route tables: traffic from public subnet routes through the firewall endpoint before reaching the IGW.

**Terraform example:**

```hcl
resource "aws_networkfirewall_firewall" "main" {
  name                = "prod-network-firewall"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.main.arn
  vpc_id              = aws_vpc.main.id

  subnet_mapping {
    subnet_id = aws_subnet.firewall_az1.id
  }
}

resource "aws_networkfirewall_rule_group" "domain_block" {
  capacity = 100
  name     = "block-malicious-domains"
  type     = "STATEFUL"

  rule_group {
    rules_source {
      rules_source_list {
        generated_rules_type = "DENYLIST"
        target_types         = ["HTTP_HOST", "TLS_SNI"]
        targets = [
          "malware-c2.example.com",
          "phishing-kit.badactor.net",
          ".onion.ly",
        ]
      }
    }
  }
}

resource "aws_networkfirewall_rule_group" "rate_limit" {
  capacity = 100
  name     = "rate-limit-scanning"
  type     = "STATEFUL"

  rule_group {
    rules_source {
      # Suricata-compatible rule: alert on >100 new connections/min from single IP
      stateful_rule {
        action = "DROP"
        header {
          destination      = "ANY"
          destination_port = "ANY"
          direction        = "ANY"
          protocol         = "TCP"
          source           = "ANY"
          source_port      = "ANY"
        }
        rule_option {
          keyword  = "sid"
          settings = ["1000001"]
        }
      }
    }
  }
}

resource "aws_networkfirewall_firewall_policy" "main" {
  name = "prod-firewall-policy"

  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]

    stateful_rule_group_reference {
      resource_arn = aws_networkfirewall_rule_group.domain_block.arn
    }
    stateful_rule_group_reference {
      resource_arn = aws_networkfirewall_rule_group.rate_limit.arn
    }
  }
}
```

**Route table configuration (inspection VPC pattern):**

```bash
# Route from public subnet to firewall endpoint (replace with actual endpoint ID)
aws ec2 create-route \
  --route-table-id rtb-public \
  --destination-cidr-block 0.0.0.0/0 \
  --vpc-endpoint-id vpce-firewall-az1

# Route from firewall subnet to IGW
aws ec2 create-route \
  --route-table-id rtb-firewall \
  --destination-cidr-block 0.0.0.0/0 \
  --gateway-id igw-0abc123
```

---

### VPC Flow Logs

VPC Flow Logs capture metadata about IP traffic to/from ENIs, subnets, or entire VPCs. They do NOT capture packet payloads.

**Enable Flow Logs:**

```bash
# Enable flow logs to CloudWatch Logs
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-0abc123 \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name /aws/vpc/flowlogs \
  --deliver-logs-permission-arn arn:aws:iam::123456789012:role/flowlogs-role

# Enable flow logs to S3 (recommended for Athena queries)
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-0abc123 \
  --traffic-type ALL \
  --log-destination-type s3 \
  --log-destination arn:aws:s3:::my-flowlogs-bucket/vpc-logs/ \
  --log-format '${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}'
```

**Flow Log fields:**

| Field | Description |
|---|---|
| version | Flow log version |
| account-id | AWS account ID |
| interface-id | ENI ID |
| srcaddr | Source IP |
| dstaddr | Destination IP |
| srcport | Source port |
| dstport | Destination port |
| protocol | IANA protocol number (6=TCP, 17=UDP, 1=ICMP) |
| packets | Packet count |
| bytes | Byte count |
| start / end | Unix timestamps |
| action | ACCEPT or REJECT |
| log-status | OK, NODATA, SKIPDATA |

**Athena queries for threat hunting:**

```sql
-- Create Athena table for flow logs in S3
CREATE EXTERNAL TABLE vpc_flow_logs (
  version int, account string, interfaceid string,
  sourceaddress string, destinationaddress string,
  sourceport int, destinationport int, protocol int,
  numpackets int, numbytes bigint, starttime int, endtime int,
  action string, logstatus string
)
ROW FORMAT DELIMITED FIELDS TERMINATED BY ' '
LOCATION 's3://my-flowlogs-bucket/vpc-logs/';

-- Top rejected traffic sources (potential scanners/attackers)
SELECT sourceaddress, COUNT(*) AS rejected_flows, SUM(numbytes) AS total_bytes
FROM vpc_flow_logs
WHERE action = 'REJECT'
  AND date_partition = '2024/01/15'
GROUP BY sourceaddress
ORDER BY rejected_flows DESC
LIMIT 25;

-- Port scanning detection: single source hitting many distinct destination ports
SELECT sourceaddress, destinationaddress,
       COUNT(DISTINCT destinationport) AS unique_ports,
       COUNT(*) AS total_flows
FROM vpc_flow_logs
WHERE protocol = 6
  AND action = 'REJECT'
  AND date_partition = '2024/01/15'
GROUP BY sourceaddress, destinationaddress
HAVING COUNT(DISTINCT destinationport) > 20
ORDER BY unique_ports DESC;

-- Data exfiltration detection: high outbound bytes to external IPs
SELECT sourceaddress, destinationaddress,
       SUM(numbytes) AS total_bytes,
       COUNT(*) AS flow_count
FROM vpc_flow_logs
WHERE action = 'ACCEPT'
  AND sourceaddress LIKE '10.%'           -- internal source
  AND destinationaddress NOT LIKE '10.%'  -- external destination
  AND date_partition = '2024/01/15'
GROUP BY sourceaddress, destinationaddress
HAVING SUM(numbytes) > 1073741824         -- > 1 GB
ORDER BY total_bytes DESC;

-- Connections to unusual ports (potential C2 or data exfil)
SELECT destinationaddress, destinationport, COUNT(*) AS flows
FROM vpc_flow_logs
WHERE action = 'ACCEPT'
  AND sourceaddress LIKE '10.%'
  AND destinationport NOT IN (80, 443, 53, 123, 22, 25, 587)
  AND destinationaddress NOT LIKE '10.%'
GROUP BY destinationaddress, destinationport
ORDER BY flows DESC
LIMIT 50;
```

---

### AWS WAF v2

AWS WAF v2 is a web application firewall that can be attached to ALBs, CloudFront, API Gateway, AppSync, and Cognito.

**Full WAF WebACL configuration (JSON):**

```json
{
  "Name": "prod-waf-webacl",
  "Scope": "REGIONAL",
  "DefaultAction": { "Allow": {} },
  "Rules": [
    {
      "Name": "AWSManagedRulesCommonRuleSet",
      "Priority": 10,
      "OverrideAction": { "None": {} },
      "Statement": {
        "ManagedRuleGroupStatement": {
          "VendorName": "AWS",
          "Name": "AWSManagedRulesCommonRuleSet"
        }
      },
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "CommonRuleSet"
      }
    },
    {
      "Name": "AWSManagedRulesKnownBadInputsRuleSet",
      "Priority": 20,
      "OverrideAction": { "None": {} },
      "Statement": {
        "ManagedRuleGroupStatement": {
          "VendorName": "AWS",
          "Name": "AWSManagedRulesKnownBadInputsRuleSet"
        }
      },
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "KnownBadInputs"
      }
    },
    {
      "Name": "AWSManagedRulesSQLiRuleSet",
      "Priority": 30,
      "OverrideAction": { "None": {} },
      "Statement": {
        "ManagedRuleGroupStatement": {
          "VendorName": "AWS",
          "Name": "AWSManagedRulesSQLiRuleSet"
        }
      },
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "SQLiRuleSet"
      }
    },
    {
      "Name": "RateLimitPerIP",
      "Priority": 40,
      "Action": { "Block": {} },
      "Statement": {
        "RateBasedStatement": {
          "Limit": 2000,
          "AggregateKeyType": "IP",
          "EvaluationWindowSec": 300
        }
      },
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "RateLimitPerIP"
      }
    }
  ]
}
```

**Deploy WAF and associate with ALB:**

```bash
# Create WebACL from JSON file
aws wafv2 create-web-acl --cli-input-json file://waf-webacl.json --region us-east-1

# Associate WAF with ALB
aws wafv2 associate-web-acl \
  --web-acl-arn arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-waf-webacl/abc123 \
  --resource-arn arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-alb/abc

# Enable WAF logging to S3
aws wafv2 put-logging-configuration \
  --logging-configuration '{
    "ResourceArn": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-waf-webacl/abc123",
    "LogDestinationConfigs": ["arn:aws:s3:::my-waf-logs-bucket"]
  }'
```

**AWS WAF Managed Rule Groups:**

| Rule Group | Description |
|---|---|
| AWSManagedRulesCommonRuleSet | OWASP Top 10 protections (XSS, path traversal, LFI, RCE) |
| AWSManagedRulesKnownBadInputsRuleSet | Log4j, Spring4Shell, SSRF patterns |
| AWSManagedRulesSQLiRuleSet | SQL injection patterns across common databases |
| AWSManagedRulesLinuxRuleSet | Linux-specific exploitation patterns |
| AWSManagedRulesUnixRuleSet | POSIX/Unix-specific attacks |
| AWSManagedRulesWindowsRuleSet | Windows exploitation (PowerShell, path traversal) |
| AWSManagedRulesPHPRuleSet | PHP-specific vulnerabilities |
| AWSManagedRulesWordPressRuleSet | WordPress-specific attack patterns |
| AWSManagedRulesAdminProtectionRuleSet | Protect admin panels from external access |
| AWSManagedRulesBotControlRuleSet | Bot detection and management |
| AWSManagedRulesATPRuleSet | Account Takeover Prevention (credential stuffing) |
| AWSManagedRulesACFPRuleSet | Account Creation Fraud Prevention |
| AWSManagedRulesAmazonIpReputationList | AWS threat intelligence IP blocklist |
| AWSManagedRulesAnonymousIpList | Tor, VPN, hosting providers, open proxies |

---

### GuardDuty Network Findings

Amazon GuardDuty uses threat intelligence, ML, and anomaly detection to identify malicious network activity in VPC Flow Logs, DNS logs, and CloudTrail.

**Network-relevant GuardDuty findings:**

| Finding Type | Description | Recommended Response |
|---|---|---|
| `Recon:EC2/PortProbeUnprotectedPort` | External IP is probing unprotected ports on an EC2 instance | Review SG rules; ensure no unnecessary ports exposed; check for unexpected services |
| `Recon:EC2/Portscan` | EC2 instance is port scanning other hosts (outbound) | Instance may be compromised; isolate, take memory snapshot, investigate |
| `UnauthorizedAccess:EC2/TorClient` | EC2 instance is communicating with Tor network exit nodes | Treat as compromise indicator; isolate instance; investigate for lateral movement |
| `UnauthorizedAccess:EC2/TorRelay` | EC2 instance is functioning as a Tor relay | Treat as compromise; instance likely used for anonymization infrastructure |
| `Trojan:EC2/DNSDataExfiltration` | EC2 instance is exfiltrating data through DNS queries | Block DNS exfiltration via Route 53 Resolver DNS Firewall; isolate instance |
| `Backdoor:EC2/C&CActivity.B!DNS` | EC2 instance is communicating with C2 via DNS | Immediate isolation; full forensic investigation; credential rotation |
| `Behavior:EC2/NetworkPortUnusual` | EC2 instance is communicating on an unusual port for the instance profile | Review what process is using the port; compare with baseline |
| `Trojan:EC2/DropPoint` | EC2 is communicating with a known malware drop site | Isolate; investigate for data staging and exfiltration |
| `Impact:EC2/MaliciousDomainRequest.Reputation` | DNS request to a known malicious domain | Block domain; review process making requests; investigate for compromise |
| `UnauthorizedAccess:EC2/SSHBruteForce` | Brute force SSH attempts against EC2 from external IP | Block source IP via NACL/WAF; disable password auth; enforce key-based auth |

```bash
# List active GuardDuty findings filtered by network types
aws guardduty list-findings \
  --detector-id <detector-id> \
  --finding-criteria '{
    "Criterion": {
      "type": {
        "Prefix": ["Recon:EC2", "UnauthorizedAccess:EC2", "Trojan:EC2", "Backdoor:EC2"]
      },
      "severity": { "Gte": 7.0 }
    }
  }'

# Suppress low-severity port probe findings from known scanner (e.g., internal security scanner)
aws guardduty create-filter \
  --detector-id <detector-id> \
  --name "suppress-internal-scanner" \
  --action ARCHIVE \
  --finding-criteria '{
    "Criterion": {
      "type": { "Eq": ["Recon:EC2/PortProbeUnprotectedPort"] },
      "service.action.portProbeAction.portProbeDetails.remoteIpDetails.ipAddressV4": {
        "Eq": ["10.1.2.3"]
      }
    }
  }'
```

---

### AWS PrivateLink

AWS PrivateLink (Interface VPC Endpoints) allows you to access AWS services and third-party services over private network connections, keeping traffic entirely within the AWS network.

**Advantages over VPC Peering for service access:**

| Feature | VPC Peering | PrivateLink |
|---|---|---|
| Transitive routing | Not supported | Supported |
| Service exposure granularity | Entire VPC CIDR | Specific service/port only |
| Overlapping CIDRs | Not supported | Supported |
| Direction | Bidirectional | Unidirectional (consumer to provider) |
| Scale | Limited by peering connections | Scales to millions of consumers |

```bash
# Create Interface Endpoint for Secrets Manager
aws ec2 create-vpc-endpoint \
  --vpc-id vpc-0abc123 \
  --vpc-endpoint-type Interface \
  --service-name com.amazonaws.us-east-1.secretsmanager \
  --subnet-ids subnet-0priv1 subnet-0priv2 \
  --security-group-ids sg-endpoints \
  --private-dns-enabled \
  --tag-specifications 'ResourceType=vpc-endpoint,Tags=[{Key=Name,Value=secretsmanager-endpoint}]'

# List available endpoint services
aws ec2 describe-vpc-endpoint-services \
  --query 'ServiceDetails[*].[ServiceName,ServiceType[0]]' \
  --output table
```

**S3 bucket policy enforcing VPC Endpoint access only (prevent direct internet access):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyNonVPCEndpointAccess",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::my-sensitive-bucket",
        "arn:aws:s3:::my-sensitive-bucket/*"
      ],
      "Condition": {
        "StringNotEquals": {
          "aws:sourceVpce": "vpce-0abc123def456"
        }
      }
    }
  ]
}
```

```bash
# Apply the bucket policy
aws s3api put-bucket-policy \
  --bucket my-sensitive-bucket \
  --policy file://s3-vpc-endpoint-policy.json

# Verify endpoint DNS resolution works from inside VPC
# (should resolve to private IP, not public S3 endpoint)
nslookup my-sensitive-bucket.s3.amazonaws.com
```

---

## Azure Network Security

### VNet and NSG

An Azure Virtual Network (VNet) is the fundamental network isolation unit. Network Security Groups (NSGs) are **stateful** packet filters applied at the subnet level or directly to individual NICs. Return traffic is automatically permitted.

**Create VNet and NSG via Azure CLI:**

```bash
# Create resource group
az group create --name prod-rg --location eastus

# Create VNet with address space
az network vnet create \
  --resource-group prod-rg \
  --name prod-vnet \
  --address-prefixes 10.0.0.0/16 \
  --subnet-name app-subnet \
  --subnet-prefixes 10.0.10.0/24

# Add additional subnets
az network vnet subnet create \
  --resource-group prod-rg \
  --vnet-name prod-vnet \
  --name data-subnet \
  --address-prefixes 10.0.20.0/24

# Create NSG
az network nsg create \
  --resource-group prod-rg \
  --name app-nsg

# Add inbound rule: allow HTTPS from internet
az network nsg rule create \
  --resource-group prod-rg \
  --nsg-name app-nsg \
  --name Allow-HTTPS-Inbound \
  --priority 100 \
  --protocol Tcp \
  --direction Inbound \
  --source-address-prefixes Internet \
  --source-port-ranges '*' \
  --destination-address-prefixes VirtualNetwork \
  --destination-port-ranges 443 \
  --access Allow

# Add inbound rule: deny all other inbound (explicit deny)
az network nsg rule create \
  --resource-group prod-rg \
  --nsg-name app-nsg \
  --name Deny-All-Inbound \
  --priority 4096 \
  --protocol '*' \
  --direction Inbound \
  --source-address-prefixes '*' \
  --source-port-ranges '*' \
  --destination-address-prefixes '*' \
  --destination-port-ranges '*' \
  --access Deny

# Associate NSG with subnet
az network vnet subnet update \
  --resource-group prod-rg \
  --vnet-name prod-vnet \
  --name app-subnet \
  --network-security-group app-nsg
```

**Enable NSG Flow Logs with Traffic Analytics:**

```bash
# Create storage account for flow logs
az storage account create \
  --resource-group prod-rg \
  --name prodflowlogssa \
  --sku Standard_LRS \
  --kind StorageV2

# Enable NSG flow logs (v2 includes byte/packet counts)
az network watcher flow-log create \
  --resource-group prod-rg \
  --name app-nsg-flowlog \
  --nsg app-nsg \
  --storage-account prodflowlogssa \
  --enabled true \
  --format JSON \
  --log-version 2 \
  --retention 30

# Enable Traffic Analytics (requires Log Analytics workspace)
az network watcher flow-log update \
  --resource-group prod-rg \
  --name app-nsg-flowlog \
  --workspace /subscriptions/<sub-id>/resourceGroups/prod-rg/providers/Microsoft.OperationalInsights/workspaces/prod-law \
  --traffic-analytics true \
  --interval 10
```

**Hub-Spoke topology overview:**

The hub VNet contains shared services (Azure Firewall, VPN/ExpressRoute gateway, DNS, Bastion). Spoke VNets contain workloads and peer to the hub. Traffic between spokes is forced through the hub firewall via User Defined Routes (UDRs), providing centralized inspection. This is the recommended topology for enterprise Azure deployments.

```bash
# Create VNet peering (hub to spoke)
az network vnet peering create \
  --resource-group hub-rg \
  --name hub-to-spoke1 \
  --vnet-name hub-vnet \
  --remote-vnet /subscriptions/<sub>/resourceGroups/spoke1-rg/providers/Microsoft.Network/virtualNetworks/spoke1-vnet \
  --allow-vnet-access \
  --allow-forwarded-traffic \
  --allow-gateway-transit  # Hub provides gateway to spoke

# UDR to force spoke traffic through Azure Firewall
az network route-table create --resource-group spoke1-rg --name spoke1-rt
az network route-table route create \
  --resource-group spoke1-rg \
  --route-table-name spoke1-rt \
  --name default-to-firewall \
  --address-prefix 0.0.0.0/0 \
  --next-hop-type VirtualAppliance \
  --next-hop-ip-address 10.0.0.4  # Azure Firewall private IP
```

---

### Azure Firewall Premium

Azure Firewall Premium adds TLS inspection, IDPS (Intrusion Detection and Prevention System), URL filtering, and web categories on top of Standard features.

```bash
# Create Firewall Policy with Premium SKU
az network firewall policy create \
  --resource-group hub-rg \
  --name prod-firewall-policy \
  --sku Premium \
  --threat-intel-mode Deny

# Enable IDPS in Deny mode
az network firewall policy update \
  --resource-group hub-rg \
  --name prod-firewall-policy \
  --idps-mode Deny

# Configure IDPS signature overrides — set high-severity sigs to Alert+Deny
az network firewall policy intrusion-detection add \
  --policy-name prod-firewall-policy \
  --resource-group hub-rg \
  --mode Deny \
  --signature-id 2013028  # Example: ET MALWARE known trojan
```

**IDPS Signature Categories to set Alert+Deny:**

| Category | Description |
|---|---|
| Botnet | Traffic patterns associated with known botnet C2 |
| CnC | Command and Control communication |
| DoS | Denial of Service attack patterns |
| Exploit | Known CVE exploitation attempts |
| Malware | Malware download and distribution patterns |
| Phishing | Phishing infrastructure communication |
| Scan | Network scanning and reconnaissance |
| Trojan | Trojan horse malware communications |
| WebAttack | Web application attack patterns |
| Backdoor | Backdoor and RAT communication patterns |

```bash
# Enable TLS inspection (requires intermediate CA certificate in Key Vault)
az network firewall policy update \
  --resource-group hub-rg \
  --name prod-firewall-policy \
  --key-vault-secret-id https://prod-kv.vault.azure.net/secrets/firewall-ca-cert

# Create application rule collection for URL filtering
az network firewall policy rule-collection-group collection add-filter-collection \
  --policy-name prod-firewall-policy \
  --resource-group hub-rg \
  --rule-collection-group-name DefaultApplicationRuleCollectionGroup \
  --name AllowedWebCategories \
  --collection-priority 200 \
  --action Allow \
  --rule-name AllowBusinessWebCategories \
  --rule-type ApplicationRule \
  --source-addresses 10.0.0.0/8 \
  --protocols Http=80 Https=443 \
  --web-categories "Business" "ComputersAndTechnology" "Finance"
```

---

### Azure Private Endpoints

Azure Private Endpoints provide a private IP address from your VNet for Azure PaaS services (Azure SQL, Storage, Key Vault, etc.) using PrivateLink technology.

```bash
# Disable public network access on Azure SQL before creating private endpoint
az sql server update \
  --resource-group prod-rg \
  --name prod-sql-server \
  --set publicNetworkAccess=Disabled

# Create Private Endpoint for Azure SQL
az network private-endpoint create \
  --resource-group prod-rg \
  --name sql-private-endpoint \
  --vnet-name prod-vnet \
  --subnet data-subnet \
  --private-connection-resource-id /subscriptions/<sub>/resourceGroups/prod-rg/providers/Microsoft.Sql/servers/prod-sql-server \
  --group-id sqlServer \
  --connection-name sql-private-connection

# Create Private DNS Zone for Azure SQL
az network private-dns zone create \
  --resource-group prod-rg \
  --name "privatelink.database.windows.net"

# Link DNS Zone to VNet
az network private-dns link vnet create \
  --resource-group prod-rg \
  --zone-name "privatelink.database.windows.net" \
  --name prod-vnet-dns-link \
  --virtual-network prod-vnet \
  --registration-enabled false

# Create DNS Zone Group to auto-register private endpoint IP
az network private-endpoint dns-zone-group create \
  --resource-group prod-rg \
  --endpoint-name sql-private-endpoint \
  --name sql-dns-zone-group \
  --private-dns-zone "privatelink.database.windows.net" \
  --zone-name sql
```

**Private DNS Zones by service:**

| Azure Service | Private DNS Zone |
|---|---|
| Azure SQL | privatelink.database.windows.net |
| Azure Storage (blob) | privatelink.blob.core.windows.net |
| Azure Key Vault | privatelink.vaultcore.azure.net |
| Azure Container Registry | privatelink.azurecr.io |
| Azure Kubernetes Service | privatelink.eastus.azmk8s.io |
| Azure Monitor | privatelink.monitor.azure.com |

---

### Azure DDoS Protection Standard

Azure DDoS Protection Standard provides adaptive DDoS protection tuned specifically for your Azure resources.

```bash
# Create DDoS Protection Plan
az network ddos-protection create \
  --resource-group prod-rg \
  --name prod-ddos-plan \
  --location eastus

# Enable DDoS Standard on VNet
az network vnet update \
  --resource-group prod-rg \
  --name prod-vnet \
  --ddos-protection true \
  --ddos-protection-plan /subscriptions/<sub>/resourceGroups/prod-rg/providers/Microsoft.Network/ddosProtectionPlans/prod-ddos-plan

# Create DDoS alert for volumetric attack
az monitor metrics alert create \
  --resource-group prod-rg \
  --name ddos-under-attack-alert \
  --scopes /subscriptions/<sub>/resourceGroups/prod-rg/providers/Microsoft.Network/publicIPAddresses/prod-pip \
  --condition "avg UnderDDoSAttack > 0" \
  --window-size 5m \
  --evaluation-frequency 1m \
  --action /subscriptions/<sub>/resourceGroups/prod-rg/providers/microsoft.insights/actionGroups/SecurityTeamAG
```

**DDoS Protection Standard features:**

| Feature | Description |
|---|---|
| Adaptive tuning | ML-based policy tuned to your specific traffic baseline |
| Always-on monitoring | Real-time traffic monitoring with automatic mitigation |
| Attack metrics | Per-resource attack telemetry and mitigation logs |
| DDoS Rapid Response (DRR) | Access to Microsoft DDoS specialists during active attacks |
| Attack analytics | Post-attack reports and flow-level visibility |
| Cost protection | Service credit for scale-out costs during verified attacks |
| Multi-layered mitigation | Volumetric, protocol, and resource layer attack mitigation |

**Cost reference:** Azure DDoS Protection Standard is priced per protection plan (~$2,944/month for the plan) plus a per-resource fee for public IPs. Evaluate against the cost of downtime for your workload.

---

### Azure Front Door and WAF

Azure Front Door with WAF provides global Layer 7 DDoS protection, WAF, and CDN capabilities.

**WAF Policy (JSON — Bicep-compatible):**

```json
{
  "name": "prodWAFPolicy",
  "properties": {
    "policySettings": {
      "enabledState": "Enabled",
      "mode": "Prevention",
      "requestBodyCheck": "Enabled"
    },
    "managedRules": {
      "managedRuleSets": [
        {
          "ruleSetType": "Microsoft_DefaultRuleSet",
          "ruleSetVersion": "2.1",
          "ruleSetAction": "Block"
        },
        {
          "ruleSetType": "Microsoft_BotManagerRuleSet",
          "ruleSetVersion": "1.0",
          "ruleSetAction": "Block"
        }
      ]
    },
    "customRules": {
      "rules": [
        {
          "name": "RateLimitPerIP",
          "priority": 1,
          "ruleType": "RateLimitRule",
          "rateLimitDurationInMinutes": 1,
          "rateLimitThreshold": 1000,
          "matchConditions": [
            {
              "matchVariable": "RemoteAddr",
              "operator": "IPMatch",
              "negateCondition": true,
              "matchValue": ["10.0.0.0/8", "172.16.0.0/12"]
            }
          ],
          "action": "Block"
        }
      ]
    }
  }
}
```

```bash
# Create WAF policy
az network front-door waf-policy create \
  --resource-group prod-rg \
  --name prodWAFPolicy \
  --mode Prevention \
  --sku Premium_AzureFrontDoor

# Add managed rule sets
az network front-door waf-policy managed-rules add \
  --resource-group prod-rg \
  --policy-name prodWAFPolicy \
  --type Microsoft_DefaultRuleSet \
  --version 2.1

az network front-door waf-policy managed-rules add \
  --resource-group prod-rg \
  --policy-name prodWAFPolicy \
  --type Microsoft_BotManagerRuleSet \
  --version 1.0
```

**Azure Front Door WAF Managed Rule Sets:**

| Rule Set | Version | Description |
|---|---|---|
| Microsoft_DefaultRuleSet | 2.1 | OWASP CRS 3.2 + Microsoft custom rules; covers SQLI, XSS, RCE, RFI, LFI |
| Microsoft_BotManagerRuleSet | 1.0 | Bot classification (good bots, bad bots, unknown) with allow/block actions |

---

## GCP Network Security

### Custom Mode VPC

GCP VPCs are global (not regional), but subnets are regional. **Always use custom mode VPC** — auto mode creates subnets in every region using the same predictable CIDR blocks (/20 from 10.128.0.0/9), which reduces segmentation and creates overlap risks.

```bash
# Create custom mode VPC (no auto subnets)
gcloud compute networks create prod-vpc \
  --subnet-mode=custom \
  --bgp-routing-mode=regional

# Create regional subnet with Private Google Access enabled
# Private Google Access allows VMs without external IPs to reach Google APIs
gcloud compute networks subnets create app-subnet-us-east1 \
  --network=prod-vpc \
  --region=us-east1 \
  --range=10.10.0.0/24 \
  --enable-private-ip-google-access \
  --enable-flow-logs \
  --logging-aggregation-interval=interval-5-sec \
  --logging-flow-sampling=0.5

# Create data subnet (no Private Google Access needed for DB tier)
gcloud compute networks subnets create data-subnet-us-east1 \
  --network=prod-vpc \
  --region=us-east1 \
  --range=10.10.10.0/24
```

**Firewall rule design — GCP uses tags and service accounts:**

```bash
# Baseline: deny all ingress (GCP default is implied deny, but make it explicit)
gcloud compute firewall-rules create prod-deny-all-ingress \
  --network=prod-vpc \
  --direction=INGRESS \
  --priority=65534 \
  --action=DENY \
  --rules=all \
  --source-ranges=0.0.0.0/0

# Allow Google health checks (required for load balancers)
gcloud compute firewall-rules create prod-allow-health-checks \
  --network=prod-vpc \
  --direction=INGRESS \
  --priority=1000 \
  --action=ALLOW \
  --rules=tcp:8080 \
  --source-ranges=35.191.0.0/16,130.211.0.0/22 \
  --target-tags=app-server

# Allow app tier to reach database using network tags
gcloud compute firewall-rules create prod-allow-app-to-db \
  --network=prod-vpc \
  --direction=INGRESS \
  --priority=1000 \
  --action=ALLOW \
  --rules=tcp:5432 \
  --source-tags=app-server \
  --target-tags=db-server

# Allow internal SSH only from IAP (Identity-Aware Proxy) — no bastion needed
gcloud compute firewall-rules create prod-allow-iap-ssh \
  --network=prod-vpc \
  --direction=INGRESS \
  --priority=1000 \
  --action=ALLOW \
  --rules=tcp:22 \
  --source-ranges=35.235.240.0/20 \  # IAP IP range
  --target-tags=app-server
```

**Assign tags to instances:**

```bash
gcloud compute instances add-tags app-instance-1 \
  --tags=app-server \
  --zone=us-east1-b

gcloud compute instances add-tags db-instance-1 \
  --tags=db-server \
  --zone=us-east1-b
```

---

### Cloud Armor

Google Cloud Armor is GCP's WAF and DDoS protection service, attached to global external HTTP(S) load balancers.

```bash
# Create a security policy
gcloud compute security-policies create prod-security-policy \
  --description="Production WAF policy"

# Add pre-configured OWASP CRS rules — XSS protection
gcloud compute security-policies rules create 1000 \
  --security-policy=prod-security-policy \
  --expression="evaluatePreconfiguredExpr('xss-stable')" \
  --action=deny-403 \
  --description="Block XSS attacks"

# Add SQLi protection
gcloud compute security-policies rules create 1010 \
  --security-policy=prod-security-policy \
  --expression="evaluatePreconfiguredExpr('sqli-stable')" \
  --action=deny-403 \
  --description="Block SQL injection"

# Add LFI protection
gcloud compute security-policies rules create 1020 \
  --security-policy=prod-security-policy \
  --expression="evaluatePreconfiguredExpr('lfi-stable')" \
  --action=deny-403 \
  --description="Block Local File Inclusion"

# Add RCE protection
gcloud compute security-policies rules create 1030 \
  --security-policy=prod-security-policy \
  --expression="evaluatePreconfiguredExpr('rce-stable')" \
  --action=deny-403 \
  --description="Block Remote Code Execution"

# Add rate-based ban: if source IP exceeds 1000 req/sec, ban for 120s
gcloud compute security-policies rules create 900 \
  --security-policy=prod-security-policy \
  --expression="true" \
  --action=rate-based-ban \
  --rate-limit-threshold-count=1000 \
  --rate-limit-threshold-interval-sec=1 \
  --ban-duration-sec=120 \
  --conform-action=allow \
  --exceed-action=deny-429 \
  --enforce-on-key=IP \
  --description="Rate limit and ban abusive IPs"

# Attach security policy to backend service
gcloud compute backend-services update prod-backend-service \
  --security-policy=prod-security-policy \
  --global
```

**Cloud Armor pre-configured rule sets:**

| Rule Set Expression | Description |
|---|---|
| `xss-stable` | Cross-Site Scripting (OWASP CRS) |
| `sqli-stable` | SQL Injection (OWASP CRS) |
| `lfi-stable` | Local File Inclusion |
| `rfi-stable` | Remote File Inclusion |
| `rce-stable` | Remote Code Execution |
| `methodenforcement-stable` | HTTP method enforcement |
| `scannerdetection-stable` | Scanner detection |
| `protocolattack-stable` | Protocol-level attacks |
| `php-stable` | PHP-specific attacks |
| `sessionfixation-stable` | Session fixation attacks |
| `java-stable` | Java deserialization attacks |
| `nodejs-stable` | Node.js attacks |
| `cve-canary` | High-profile CVEs (Log4Shell, Spring4Shell) |

---

### VPC Service Controls

VPC Service Controls create a security perimeter around Google Cloud services (GCS, BigQuery, Cloud SQL, etc.) to prevent data exfiltration, even from compromised credentials.

```bash
# List existing access policies (one per organization)
gcloud access-context-manager policies list --organization=<org-id>

# Create a service perimeter to protect GCS and BigQuery
gcloud access-context-manager perimeters create prod-perimeter \
  --policy=<policy-name> \
  --title="Production Data Perimeter" \
  --resources=projects/<project-number> \
  --restricted-services=storage.googleapis.com,bigquery.googleapis.com \
  --access-levels=<policy-name>/accessLevels/corp-network-level

# Create access level for corporate network
gcloud access-context-manager levels create corp-network-level \
  --policy=<policy-name> \
  --title="Corporate Network" \
  --basic-level-spec=corp-network-conditions.yaml
```

**corp-network-conditions.yaml:**

```yaml
conditions:
  - ipSubnetworks:
      - "203.0.113.0/24"    # corporate egress IP range
      - "198.51.100.0/24"   # VPN IP range
```

**VPC-SC perimeter in dry run mode (for testing):**

```bash
# Enable dry run (logs violations without blocking) before enforcing
gcloud access-context-manager perimeters dry-run create prod-perimeter \
  --policy=<policy-name> \
  --resources=projects/<project-number> \
  --restricted-services=storage.googleapis.com,bigquery.googleapis.com

# Check dry run violation logs
gcloud logging read 'protoPayload.serviceName="storage.googleapis.com" AND protoPayload.status.code=7' \
  --project=<project-id> \
  --limit=50
```

---

### GCP VPC Flow Logs

GCP VPC Flow Logs are enabled per subnet and capture sampled flow records. Logs are sent to Cloud Logging and can be exported to BigQuery for analysis.

```bash
# Enable flow logs on existing subnet
gcloud compute networks subnets update app-subnet-us-east1 \
  --region=us-east1 \
  --enable-flow-logs \
  --logging-aggregation-interval=interval-5-sec \
  --logging-flow-sampling=1.0 \
  --logging-metadata=include-all

# Export flow logs to BigQuery for analysis
gcloud logging sinks create vpc-flowlogs-bq \
  bigquery.googleapis.com/projects/<project-id>/datasets/vpc_flow_logs \
  --log-filter='resource.type="gce_subnetwork" AND logName="projects/<project-id>/logs/compute.googleapis.com%2Fvpc_flows"'
```

**BigQuery query for unusual outbound connections:**

```sql
-- Unusual outbound ports from internal VMs (not 80, 443, 53, 123)
SELECT
  jsonPayload.connection.src_ip AS src_ip,
  jsonPayload.connection.dest_ip AS dest_ip,
  jsonPayload.connection.dest_port AS dest_port,
  jsonPayload.connection.protocol AS protocol,
  SUM(CAST(jsonPayload.bytes_sent AS INT64)) AS total_bytes,
  COUNT(*) AS flow_count
FROM `project.dataset.compute_googleapis_com_vpc_flows_*`
WHERE
  _TABLE_SUFFIX BETWEEN '20240115' AND '20240116'
  AND jsonPayload.reporter = 'SRC'
  AND STARTS_WITH(jsonPayload.connection.src_ip, '10.')
  AND NOT STARTS_WITH(jsonPayload.connection.dest_ip, '10.')
  AND CAST(jsonPayload.connection.dest_port AS INT64) NOT IN (80, 443, 53, 123, 22, 587, 465)
GROUP BY 1, 2, 3, 4
HAVING total_bytes > 10000000  -- > 10 MB
ORDER BY total_bytes DESC
LIMIT 100;

-- Top talkers (potential data exfiltration)
SELECT
  jsonPayload.connection.src_ip,
  jsonPayload.connection.dest_ip,
  SUM(CAST(jsonPayload.bytes_sent AS INT64)) AS bytes_sent
FROM `project.dataset.compute_googleapis_com_vpc_flows_*`
WHERE
  _TABLE_SUFFIX = '20240115'
  AND jsonPayload.reporter = 'SRC'
  AND STARTS_WITH(jsonPayload.connection.src_ip, '10.')
  AND NOT STARTS_WITH(jsonPayload.connection.dest_ip, '10.')
GROUP BY 1, 2
ORDER BY bytes_sent DESC
LIMIT 25;
```

---

## Cross-Cloud Comparison

| Control | AWS | Azure | GCP |
|---|---|---|---|
| **Virtual Network** | VPC | VNet | VPC (global) |
| **Subnet Firewall** | Security Groups (stateful, ENI) + NACLs (stateless, subnet) | NSG (stateful, subnet or NIC) | VPC Firewall Rules (stateful, network-wide, tag-based) |
| **L3/L4 Network Firewall** | AWS Network Firewall (Suricata, stateful+stateless) | Azure Firewall (FQDN filtering, threat intel) | Cloud Next Generation Firewall (Palo Alto powered) |
| **WAF** | AWS WAF v2 (ALB, CloudFront, API GW) | Azure WAF (App Gateway, Front Door) | Cloud Armor (Global LB, Managed Protection Plus) |
| **DDoS Protection** | AWS Shield Standard (free) / Shield Advanced | DDoS Basic (free) / DDoS Protection Standard | Cloud Armor Standard / Managed Protection Plus |
| **Flow Logs** | VPC Flow Logs (CloudWatch, S3, Athena) | NSG Flow Logs with Traffic Analytics (Log Analytics) | VPC Flow Logs (Cloud Logging, BigQuery) |
| **Private Connectivity** | PrivateLink (Interface Endpoints) | Private Endpoints | Private Service Connect |
| **Service Perimeter** | VPC Endpoint Policies + SCPs | Private Endpoints + Azure Policy | VPC Service Controls |
| **DNS Firewall** | Route 53 Resolver DNS Firewall | Azure Firewall DNS Proxy + DNS filtering | Cloud DNS Response Policy Zones |
| **Network IDS/NDR** | GuardDuty (VPC Flow Logs, DNS) + Traffic Mirroring | Microsoft Defender for Cloud (network layer) | Cloud IDS (Palo Alto Threat Prevention) |
| **Connectivity (on-prem)** | VPN Gateway / Direct Connect | VPN Gateway / ExpressRoute | Cloud VPN / Cloud Interconnect |
| **Transit Routing** | Transit Gateway | Azure Virtual WAN | Network Connectivity Center |
| **Patch/Access (no bastion)** | SSM Session Manager | Azure Bastion / Azure Arc | Identity-Aware Proxy (IAP) |

---

## Compliance Mappings

### NIST SP 800-53 SC Family Mapping

| Control ID | Control Name | AWS Implementation | Azure Implementation | GCP Implementation |
|---|---|---|---|---|
| SC-5 | Denial-of-Service Protection | Shield Advanced + WAF | DDoS Protection Standard + WAF | Cloud Armor Managed Protection |
| SC-7 | Boundary Protection | Security Groups + NACLs + Network Firewall | NSG + Azure Firewall | VPC Firewall + Cloud NGFW |
| SC-8 | Transmission Confidentiality | TLS enforcement via ACM + WAF | TLS policies on App Gateway | SSL policies on Load Balancer |
| SC-7(3) | Access Points | ALB + VPC Endpoints only | Private Endpoints | Private Service Connect |
| SC-7(4) | External Telecommunications Services | Direct Connect + BGP communities | ExpressRoute + route filters | Cloud Interconnect + VLAN attachments |
| SC-28 | Protection of Information at Rest | VPC Endpoint + S3 bucket policy | Private Endpoints + network deny rules | VPC Service Controls |

### CIS Cloud Benchmark Controls

| CIS Control | Description | AWS | Azure | GCP |
|---|---|---|---|---|
| CIS AWS 5.1 | No security groups allow unrestricted SSH | restricted-ssh Config rule | NSG rule audit | Firewall rule audit |
| CIS AWS 5.2 | No security groups allow unrestricted RDP | restricted-common-ports | NSG rule audit | Firewall rule audit |
| CIS AWS 5.3 | Default SG restricts all traffic | vpc-default-security-group-closed | Default NSG review | Default deny firewall rule |
| CIS AWS 3.9 | VPC flow logging enabled | VPC Flow Logs on all VPCs | NSG Flow Logs enabled | VPC Flow Logs on all subnets |
| CIS Azure 6.1 | RDP access restricted from internet | N/A | NSG deny RDP from internet | N/A |
| CIS Azure 6.5 | Network Watcher enabled | N/A | Network Watcher enabled | N/A |
| CIS GCP 3.1 | Default network not used | N/A | N/A | Custom mode VPC only |
| CIS GCP 3.6 | SSH access restricted | N/A | N/A | IAP-only SSH, deny 22 from 0.0.0.0/0 |

### MITRE ATT&CK Cloud Technique Mitigations

| ATT&CK Technique | Technique Name | AWS Control | Azure Control | GCP Control |
|---|---|---|---|---|
| T1580 | Cloud Infrastructure Discovery | GuardDuty Recon findings; restrict IAM permissions | Defender for Cloud posture alerts | SCC findings; restrict IAM |
| T1552.005 | Cloud Instance Metadata API | IMDSv2 enforcement (hop limit 1); block 169.254.169.254 | IMDS v2; disable if not needed | Metadata concealment headers |
| T1048 | Exfiltration Over Alternative Protocol | DNS Firewall + GuardDuty DNS findings | Azure Firewall DNS filtering | Cloud Armor + DNS Response Policy |
| T1071.001 | Application Layer Protocol: Web | WAF v2 + CloudFront restrictions | Azure WAF + Front Door | Cloud Armor pre-configured rules |
| T1090 | Proxy | GuardDuty Tor findings + IP reputation WAF rules | Azure Firewall threat intel | Cloud Armor anonymous IP blocking |
| T1046 | Network Service Discovery | GuardDuty PortProbe findings | Defender for Cloud network alerts | Cloud IDS |
| T1110 | Brute Force | WAF rate limiting + Shield Advanced | WAF rate limit rules | Cloud Armor rate-based ban |
| T1572 | Protocol Tunneling | Network Firewall IDS rules | Azure Firewall IDPS | Cloud IDS (Palo Alto signatures) |

---

*Last updated: 2026-04-24 | Covers AWS (us-east-1), Azure (eastus), GCP (us-east1) regional examples*
