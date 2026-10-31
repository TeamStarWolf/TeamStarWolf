# Azure CLI Reference

The Azure CLI (`az`) is the command-line tool for Microsoft Azure. It manages resource groups, virtual machines, storage, identity, networking, and secrets through a consistent verb-based syntax. This page covers sign-in, subscription selection, the common resource commands, and the output filtering that makes results scriptable. Commands follow the `az <group> <subgroup> <action>` shape.

## What it is and where it runs

The CLI is a Python program available for Linux, macOS, and Windows, and preinstalled in Azure Cloud Shell. It authenticates through `az login`, which opens a browser or accepts a device code, a service principal, or a managed identity on an Azure host. One install can hold access to several subscriptions and tenants; you pick the active one with `az account set`. Output defaults to JSON and supports JMESPath filtering with `--query`.

## Core commands

Sign in and choose a subscription.

```bash
az login                           # interactive browser or device-code sign-in
az login --use-device-code         # for headless or remote shells
az account show                    # print the active subscription and tenant
az account list --output table     # list accessible subscriptions
az account set --subscription "Prod"
```

Resource groups are the basic unit of lifecycle and access.

```bash
az group list --output table
az group create --name rg-app --location eastus
az group delete --name rg-app --no-wait --yes
```

Virtual machines with `az vm`.

```bash
az vm list --output table
az vm create --resource-group rg-app --name web1 \
  --image Ubuntu2204 --admin-username azureuser --generate-ssh-keys
az vm start --resource-group rg-app --name web1
az vm list-ip-addresses --output table
```

Storage with `az storage`.

```bash
az storage account list --output table
az storage account create --name mystg01 --resource-group rg-app --sku Standard_LRS
az storage blob list --account-name mystg01 --container-name logs --auth-mode login
```

Identity objects with `az ad`.

| Command | Purpose |
| --- | --- |
| `az ad user list` | List users in the directory |
| `az ad sp list` | List service principals |
| `az ad app create` | Register an application |
| `az ad sp create-for-rbac` | Create a service principal with an RBAC role |

```bash
az ad sp create-for-rbac --name app-ci \
  --role Reader --scopes /subscriptions/<sub-id>/resourceGroups/rg-app
```

Role assignments control access (RBAC).

```bash
az role assignment list --assignee app-ci --output table
az role assignment create --assignee <object-id> \
  --role "Storage Blob Data Reader" \
  --scope /subscriptions/<sub-id>/resourceGroups/rg-app
az role definition list --name Contributor
```

Secrets with `az keyvault`.

```bash
az keyvault create --name kv-app --resource-group rg-app --location eastus
az keyvault secret set --vault-name kv-app --name db-password --value "$NEW_VALUE"
az keyvault secret show --vault-name kv-app --name db-password --query value --output tsv
```

Networking with `az network`.

```bash
az network vnet list --output table
az network nsg rule list --resource-group rg-app --nsg-name web-nsg --output table
az network public-ip list --output table
```

Shape output with `--query` (JMESPath) and `--output`.

```bash
az vm list --query '[].{name:name,rg:resourceGroup,size:hardwareProfile.vmSize}' --output table
az account list --query "[?isDefault].id" --output tsv
```

## Common workflows

Sign in headless, set the subscription, and confirm context.

```bash
az login --use-device-code
az account set --subscription "Prod"
az account show --query '{sub:name,tenant:tenantId}' --output table
```

Find network security rules that expose RDP to the internet.

```bash
az network nsg rule list --resource-group rg-app --nsg-name web-nsg \
  --query "[?destinationPortRange=='3389' && sourceAddressPrefix=='*'].{name:name,access:access}" \
  --output table
```

Grant an app least-privilege read access to one resource group, then verify.

```bash
appid=$(az ad sp list --display-name app-ci --query '[0].id' --output tsv)
az role assignment create --assignee "$appid" \
  --role "Reader" --scope /subscriptions/<sub-id>/resourceGroups/rg-app
az role assignment list --assignee "$appid" --output table
```

Pull a database password from Key Vault into a deploy step.

```bash
pw=$(az keyvault secret show --vault-name kv-app --name db-password --query value --output tsv)
# pass $pw to the deploy tool via its environment, not the command line
```

## Flags and options worth knowing

| Flag | Effect |
| --- | --- |
| `--output json\|table\|tsv\|yaml` | Set the output format |
| `--query` | Filter and reshape output with JMESPath |
| `--subscription` | Override the active subscription for one call |
| `--resource-group` / `-g` | Target a resource group |
| `--no-wait` | Return before a long operation finishes |
| `--yes` / `-y` | Skip confirmation prompts |
| `--auth-mode login` | Use your identity for data-plane storage calls |
| `--only-show-errors` | Suppress warnings in scripted runs |
| `--verbose` / `--debug` | Increase logging detail |

## Security notes

Prefer managed identities over service-principal client secrets; a managed identity carries no secret to leak (CWE-798, use of hardcoded credentials). When a service principal is unavoidable, store its secret in Key Vault and read it at runtime rather than committing it to source or CI variables. Key Vault keeps secrets, keys, and certificates out of config files and gives you rotation and access logging.

Assign RBAC roles with `az role assignment create` scoped to the smallest resource that works, a single resource group or resource rather than the subscription, and prefer built-in roles like `Reader` over `Owner` or `Contributor`. Enforce conditional access and MFA on the identities that hold these roles. Stream Azure activity logs and Key Vault diagnostic logs to a workspace for audit so every control-plane change and secret access is recorded. See `/SECURE_CODING_REFERENCE.md` for credential-handling and least-privilege guidance.

## Resources

- Azure CLI Documentation
- Azure CLI Command Reference
- Azure Role-Based Access Control Documentation
- Azure Key Vault Documentation
- Microsoft Entra ID Documentation
- JMESPath Specification

## Related pages

- `/commands/README.md`
- `/SECURE_CODING_REFERENCE.md`
- `/commands/aws-cli.md`
- `/commands/gcloud.md`
- `/commands/jq.md`
- `/commands/terraform.md`
