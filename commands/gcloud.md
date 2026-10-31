# Google Cloud CLI (gcloud) Reference

The Google Cloud CLI (`gcloud`) is the command-line tool for Google Cloud Platform. It manages projects, compute, identity, storage, and logging through a consistent group-and-command syntax. This page covers authentication, configuration, the common resource commands, and the output controls that make results scriptable. The related `gsutil` and the newer `gcloud storage` handle Cloud Storage.

## What it is and where it runs

`gcloud` ships in the Google Cloud CLI bundle for Linux, macOS, and Windows, and is preinstalled in Cloud Shell. It authenticates with a user account through `gcloud auth login`, or with a service account, or with Application Default Credentials for client libraries. Commands follow the `gcloud <group> <command>` shape and act within an active project and configuration. Output supports filtering with `--filter` and reshaping with `--format`.

## Core commands

Authenticate your user and your application libraries.

```bash
gcloud auth login                       # sign in a user account for the CLI
gcloud auth application-default login    # credentials for client libraries (ADC)
gcloud auth list                         # show accounts and the active one
gcloud auth print-access-token           # short-lived token for the active account
```

Manage configuration and the active context.

```bash
gcloud config list                       # show the active configuration
gcloud config set project my-project
gcloud config set compute/region us-central1
gcloud config configurations create prod # a named set of settings
```

Projects.

```bash
gcloud projects list
gcloud projects describe my-project
gcloud projects get-iam-policy my-project
```

Compute with `gcloud compute`.

```bash
gcloud compute instances list
gcloud compute instances create web1 \
  --zone us-central1-a --machine-type e2-small --image-family debian-12 --image-project debian-cloud
gcloud compute firewall-rules list
gcloud compute instances describe web1 --zone us-central1-a
```

Identity and access with `gcloud iam` and the project IAM policy.

| Command | Purpose |
| --- | --- |
| `gcloud iam service-accounts list` | List service accounts in the project |
| `gcloud iam service-accounts create` | Create a service account |
| `gcloud iam roles describe` | Show the permissions in a role |
| `gcloud projects add-iam-policy-binding` | Grant a role to a member on a project |

```bash
gcloud iam service-accounts create ci-deployer --display-name "CI deployer"
gcloud projects add-iam-policy-binding my-project \
  --member serviceAccount:ci-deployer@my-project.iam.gserviceaccount.com \
  --role roles/storage.objectViewer
```

Storage with `gcloud storage` or `gsutil`.

```bash
gcloud storage buckets list
gcloud storage ls gs://my-bucket/logs/
gcloud storage cp report.csv gs://my-bucket/
gsutil iam get gs://my-bucket            # view bucket IAM policy
```

Logging.

```bash
gcloud logging logs list
gcloud logging read 'severity>=ERROR' --limit 20 --freshness 1h
gcloud logging read 'protoPayload.methodName="SetIamPolicy"' --limit 10
```

Shape output with `--format` and `--filter`.

```bash
gcloud compute instances list \
  --format='table(name,zone,status)' --filter='status=RUNNING'
gcloud projects list --format='value(projectId)'
```

## Common workflows

Set up a named configuration, then confirm the active context.

```bash
gcloud config configurations create prod
gcloud config set project my-project
gcloud config set account dana@example.com
gcloud config list
```

Find firewall rules that allow SSH from anywhere.

```bash
gcloud compute firewall-rules list \
  --filter='sourceRanges:0.0.0.0/0 AND allowed[].ports:22' \
  --format='table(name,network,sourceRanges.list())'
```

Create a least-privilege service account and grant one role, then verify.

```bash
gcloud iam service-accounts create reader --display-name "log reader"
gcloud projects add-iam-policy-binding my-project \
  --member serviceAccount:reader@my-project.iam.gserviceaccount.com \
  --role roles/logging.viewer
gcloud projects get-iam-policy my-project \
  --flatten='bindings[].members' \
  --filter='bindings.members:reader@my-project.iam.gserviceaccount.com' \
  --format='value(bindings.role)'
```

Audit recent IAM policy changes across the project.

```bash
gcloud logging read \
  'protoPayload.methodName="SetIamPolicy"' \
  --limit 20 --freshness 7d \
  --format='table(timestamp,protoPayload.authenticationInfo.principalEmail)'
```

## Flags and options worth knowing

| Flag | Effect |
| --- | --- |
| `--project` | Target a project for one command |
| `--format` | Reshape output (`table`, `json`, `yaml`, `value`, `csv`) |
| `--filter` | Server- or client-side filter on resource fields |
| `--quiet` / `-q` | Skip interactive prompts, accept defaults |
| `--impersonate-service-account` | Run as a service account via short-lived tokens |
| `--zone` / `--region` | Set location for the command |
| `--flatten` | Expand a repeated field into one row each |
| `--verbosity` | Set log detail (`debug`, `info`, `error`) |

## Security notes

A service-account key file is a long-lived credential; a leaked key grants its roles until someone revokes it (CWE-798, use of hardcoded credentials). Prefer Workload Identity Federation, attached service accounts, or `--impersonate-service-account` to get short-lived tokens, and avoid `gcloud iam service-accounts keys create` unless there is no alternative. If a key file exists, keep it out of source control, restrict its file permissions, and treat it as plaintext secret storage (CWE-312, cleartext storage of sensitive information).

Grant predefined or custom IAM roles scoped to the project or resource a member needs rather than broad roles like `roles/owner` or `roles/editor`, and bind to groups over individual users where you can. Set organization policy constraints to block risky defaults, for example disabling service-account key creation and public bucket access across the org. Enable Cloud Audit Logs (Admin Activity and Data Access) and review `SetIamPolicy` events so every access change is recorded for audit. See `/SECURE_CODING_REFERENCE.md` for credential-handling and least-privilege guidance.

## Resources

- Google Cloud CLI Documentation
- gcloud Reference
- Identity and Access Management Documentation
- Cloud Audit Logs Documentation
- Workload Identity Federation Documentation
- Organization Policy Service Documentation

## Related pages

- `/commands/README.md`
- `/SECURE_CODING_REFERENCE.md`
- `/commands/aws-cli.md`
- `/commands/azure-cli.md`
- `/commands/jq.md`
- `/commands/terraform.md`
