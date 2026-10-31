# AWS CLI Reference

The AWS CLI (`aws`) is a unified command-line tool for Amazon Web Services. It wraps the service APIs, so almost any action you can take in the console has a command. This page covers identity, storage, compute, IAM, logging, and secrets, plus the output controls that make results scriptable. Commands target AWS CLI v2.

## What it is and where it runs

The CLI is a Python-based program distributed as a standalone installer for Linux, macOS, and Windows. Calls authenticate with credentials from a profile, an environment variable, an IAM role, or AWS IAM Identity Center (SSO). Every command follows the shape `aws <service> <operation> [parameters]`. Output defaults to JSON, which pairs well with `jq` or the built-in `--query` filter.

## Core commands

Configure a profile and confirm who you are.

```bash
aws configure                      # interactive: key, secret, region, output
aws configure --profile prod       # store a named profile
aws configure sso                  # set up IAM Identity Center login
aws sts get-caller-identity        # print the account, user, and ARN in use
```

Named profiles let one machine hold several identities. Select one per command or set a default.

```bash
aws s3 ls --profile prod
export AWS_PROFILE=prod             # applies to later commands in the shell
```

Assume a role for short-lived, scoped credentials.

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::111122223333:role/Audit \
  --role-session-name review-session
```

Storage with `s3` (high level) and `s3api` (low level).

```bash
aws s3 ls s3://my-bucket/logs/     # list objects
aws s3 cp file.txt s3://my-bucket/ # upload one object
aws s3 sync ./site s3://my-bucket  # mirror a local directory
aws s3api get-bucket-policy --bucket my-bucket
aws s3api put-public-access-block --bucket my-bucket \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

Compute with `ec2`.

```bash
aws ec2 describe-instances
aws ec2 describe-security-groups
aws ec2 start-instances --instance-ids i-0abc123
aws ec2 run-instances --image-id ami-0abc --count 1 --instance-type t3.micro --dry-run
```

Identity and access with `iam`.

| Command | Purpose |
| --- | --- |
| `aws iam list-users` | List IAM users in the account |
| `aws iam list-roles` | List roles and their trust policies |
| `aws iam create-policy` | Create a managed policy from a JSON document |
| `aws iam attach-user-policy` | Attach a managed policy to a user |
| `aws iam simulate-principal-policy` | Test whether a principal is allowed an action |

```bash
aws iam create-policy --policy-name ReadLogs \
  --policy-document file://read-logs.json
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::111122223333:user/dana \
  --action-names s3:GetObject
```

Audit and observability.

```bash
aws cloudtrail lookup-events --max-results 20
aws logs describe-log-groups
aws logs tail /aws/lambda/my-func --follow     # stream recent log events
aws logs filter-log-events --log-group-name /aws/lambda/my-func --filter-pattern ERROR
```

Secrets with `secretsmanager`.

```bash
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id db/password --query SecretString --output text
aws secretsmanager create-secret --name db/password --secret-string "$NEW_VALUE"
```

Shape output with `--query` (JMESPath) and `--output`.

```bash
aws ec2 describe-instances \
  --query 'Reservations[].Instances[].{id:InstanceId,state:State.Name}' \
  --output table
aws s3api list-buckets --query 'Buckets[].Name' --output text
```

## Common workflows

Assume a role, then run commands as that role in the same shell.

```bash
creds=$(aws sts assume-role \
  --role-arn arn:aws:iam::111122223333:role/Audit \
  --role-session-name audit --query Credentials --output json)
export AWS_ACCESS_KEY_ID=$(echo "$creds" | jq -r .AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo "$creds" | jq -r .SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo "$creds" | jq -r .SessionToken)
aws sts get-caller-identity
```

Find EC2 instances exposing SSH to the world.

```bash
aws ec2 describe-security-groups \
  --filters Name=ip-permission.from-port,Values=22 \
            Name=ip-permission.cidr,Values=0.0.0.0/0 \
  --query 'SecurityGroups[].{id:GroupId,name:GroupName}' --output table
```

Review who logged in by scanning CloudTrail for console sign-ins.

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
  --max-results 50 \
  --query 'Events[].{time:EventTime,user:Username}' --output table
```

Rotate a secret, test a deploy, and confirm the new value is in place.

```bash
aws secretsmanager put-secret-value --secret-id db/password --secret-string "$NEW_VALUE"
aws secretsmanager get-secret-value --secret-id db/password \
  --query VersionId --output text
```

## Flags and options worth knowing

| Flag | Effect |
| --- | --- |
| `--profile NAME` | Use a named profile instead of the default |
| `--region NAME` | Override the region for this call |
| `--output json\|table\|text\|yaml` | Set the output format |
| `--query` | Filter and reshape output with JMESPath |
| `--dry-run` | Check permissions for `ec2` without making the change |
| `--no-cli-pager` | Print output directly instead of through a pager |
| `--debug` | Emit the full request and signing trace |
| `--cli-read-timeout` / `--cli-connect-timeout` | Bound long or stalled calls |

## Security notes

Default credentials live in plaintext at `~/.aws/credentials` (CWE-312, cleartext storage of sensitive information). Prefer IAM Identity Center or `assume-role` so the file holds no long-lived keys, and set file permissions to `600`. Never hardcode access keys in scripts, source, or CI variables (CWE-798, use of hardcoded credentials); read them from a secrets store or a role at runtime. Require MFA on roles with `--serial-number` and `--token-code`, and prefer short-lived role credentials over static user keys.

Scope IAM policies to the specific actions and resource ARNs a task needs rather than `Action: "*"` or `Resource: "*"`; test the result with `aws iam simulate-principal-policy` before you attach it. Enable CloudTrail in every region so every API call is recorded for audit, and alert on `ConsoleLogin` without MFA and on `iam` policy changes. Use `--dry-run` on `ec2` mutations to confirm authorization without side effects. See `/SECURE_CODING_REFERENCE.md` for credential-handling and least-privilege guidance.

## Resources

- AWS CLI Command Reference
- AWS CLI User Guide
- AWS Identity and Access Management User Guide
- AWS Security Best Practices (AWS Well-Architected Framework, Security Pillar)
- JMESPath Specification

## Related pages

- `/commands/README.md`
- `/SECURE_CODING_REFERENCE.md`
- `/commands/azure-cli.md`
- `/commands/gcloud.md`
- `/commands/jq.md`
- `/commands/terraform.md`
