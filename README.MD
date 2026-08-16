# Mail Authentication Record Checker

![Build and Deploy](https://github.com/JSamarxhi/mail-auth-checker/actions/workflows/deploy.yml/badge.svg)

An HTTP service that checks a domain's **SPF, DKIM and DMARC** records and reports what's missing or misconfigured.

**Live demo:** https://ca-mailcheck.purplesmoke-035a866a.eastus.azurecontainerapps.io/docs

Mail authentication is the part of a domain cutover that breaks quietly. SPF stops working at the eleventh DNS lookup, DMARC sits on `p=none` for two years, and nobody notices until mail starts landing in spam. This exposes those checks over an API.

## Stack

| Layer | Tool |
| --- | --- |
| Application | Python 3.12, FastAPI, dnspython |
| Container | Docker |
| Registry | GitHub Container Registry |
| Infrastructure | Terraform, Azure Container Apps |
| CI/CD | GitHub Actions |

## API

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/health` | Liveness probe |
| `GET` | `/check/{domain}` | Check a single domain |
| `POST` | `/check` | Check a list of domains |
| `GET` | `/docs` | Interactive OpenAPI documentation |

`GET /check/{domain}` accepts an optional `?selectors=sel1,sel2` to override the DKIM selectors tried.

```bash
curl https://ca-mailcheck.purplesmoke-035a866a.eastus.azurecontainerapps.io/check/microsoft.com
```

```json
{
  "domain": "microsoft.com",
  "spf": {
    "status": "pass",
    "record": "v=spf1 include:_spf-a.microsoft.com include:_spf-b.microsoft.com include:_spf-c.microsoft.com include:_spf-ssg-a.msft.net include:_spf1-meo.microsoft.com -all",
    "findings": []
  },
  "dkim": {
    "status": "pass",
    "selectors_found": {
      "selector2": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCPkb8bu8RGWeJGk3hJrouZXIdZ+HTp/azRp8IUOHp5wKvPUAi/54PwuLscUjRk4Rh3hjIkMpKRfJJXPxWbrT7eMLric7f/S0h+qF4aqIiQqHFCDAYfMnN6V3Wbke2U5EGm0H/cAUYkaf2AtuHJ/rdY/EXaldAm00PgT9QQMez66QIDAQAB;"
    },
    "findings": []
  },
  "dmarc": {
    "status": "pass",
    "record": "v=DMARC1; p=reject; pct=100; rua=mailto:itex-rua@microsoft.com; ruf=mailto:itex-ruf@microsoft.com; fo=1",
    "policy": "reject",
    "findings": []
  },
  "status": "pass"
}
```

Some Notes:

**DKIM selectors can't be enumerated.** There's no DNS record listing them, so the service tries the defaults used by the major senders (`selector1`/`selector2` for Microsoft 365, `google` for Workspace, `k1` for Mailchimp, and others). When it reports no DKIM found, it says so explicitly rather than claiming DKIM is absent.

**The SPF lookup limit is checked**, because that's how a working SPF record silently stops working — every `include:` costs a DNS lookup, teams add vendors over time, and at eleven the record returns `permerror` and does nothing.

**"No record" and "couldn't find out" are separate results.** `NXDOMAIN` means nothing is published; a timeout means the lookup failed. Collapsing them reports a network blip to a client as a missing SPF record.

## Running it

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Or with Docker:

```bash
docker build -t mailcheck .
docker run --rm -p 8000:8000 mailcheck
```

The image runs as a non-root user, and dependencies install in a separate layer from application code so editing source doesn't invalidate the dependency cache.

## Deployment

Pushing to `main` builds the image, pushes it to GitHub Container Registry, and runs `terraform apply` against that image.

**No stored secrets.** GitHub authenticates to Azure using OpenID Connect. Azure trusts short-lived tokens issued for this repository, so there is no client secret in the repo or its settings.

**Deployments reference the commit SHA**, not `latest`, so a running revision always maps to exactly one commit.

**The Container Apps environment is shared.** It lives in a separate resource group and Terraform configuration; this project reads it rather than managing it, so destroying this app can't affect anything else using it.

**Terraform state is in Azure Blob Storage**, shared between local runs and CI, with blob leasing to prevent two applies running at once.

## Running it on a Linux server

`deploy/` holds the configuration for running this outside a container, on an Ubuntu Server VM: a systemd unit, an nginx reverse proxy, and an SSH hardening drop-in.

The service was built that way first, by hand, before being containerized — so the same app exists as a supervised process behind nginx and as an image on a managed platform.

## Cost

The app scales to zero when idle and runs inside the Azure Container Apps monthly free grant. The only persistent cost is a few kilobytes of Terraform state in Blob Storage.

## Layout

```
.
├── app.py                       # FastAPI routes and DNS lookups
├── requirements.txt
├── Dockerfile
├── terraform/
│   └── main.tf                  # resource group and container app
├── deploy/
│   ├── mailcheck.service        # systemd unit
│   ├── nginx-mailcheck.conf     # reverse proxy
│   └── 10-hardening.conf        # sshd drop-in, key-only auth
└── .github/workflows/
    └── deploy.yml               # build, push, deploy
```

## Roadmap

- [x] SPF, DKIM and DMARC checks over an API
- [x] Running under systemd behind nginx on a Linux VM
- [x] Containerized with Docker
- [x] Deployed to Azure Container Apps
- [x] Infrastructure defined in Terraform
- [x] Build and deploy automated via GitHub Actions
- [x] Passwordless CI authentication via OIDC federated identity
- [ ] Host configuration as an Ansible playbook
- [ ] Recursive SPF lookup counting through nested includes

