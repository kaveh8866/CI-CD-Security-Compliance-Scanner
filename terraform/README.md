# Terraform / OpenTofu — OCI infrastructure

Provisions the host for the scanner on Oracle Cloud Infrastructure: a VCN, an
internet gateway, a public subnet, a two-rule security list and one Always Free
Ampere instance. **OCI is the validated target.** AWS and GCP are supported
*ports* — the mappings are documented here and in comments, but this repository
contains no test evidence for them.

```
terraform/
├── versions.tf              provider constraints + optional OCI backend
├── provider.tf              OCI provider (profile auth, no key in state)
├── main.tf                  module wiring, tags, cloud-init rendering
├── variables.tf             full input contract
├── outputs.tf               public IP, scanner URL, exposure review
├── cloud-init.yaml.tftpl    Docker + hardening; contains no secret
├── terraform.tfvars.example placeholders only
└── modules/
    ├── network/             VCN, IGW, route table, security list, subnet
    └── compute/             A1.Flex instance, VNIC IPs, image resolution
```

## Ingress contract

| Port | Source | Why |
| --- | --- | --- |
| `22/tcp` | `ssh_allowed_cidr` | administration and the deploy path |
| `8300/tcp` (`scanner_port`) | `scanner_allowed_cidr` | scanner API — **must not be `0.0.0.0/0`**, enforced by validation |

Nothing else is open. There is no 80/443 rule because this host serves no web
UI. The `scanner_allowed_cidr != 0.0.0.0/0` check exists in both the root and
module variable definitions, so a permissive tfvars edit cannot silently open
the port.

**Zero-exposure alternative:** leave `scanner_allowed_cidr` at a single address
you control *and* keep the container bound to loopback
(`SCANNER_BIND_ADDRESS=127.0.0.1` in the host `.env`), then reach the API through
`ssh -L 8300:127.0.0.1:8300`. In that mode the 8300 rule is never exercised; it
exists so the documented contract matches what an operator can actually do.

## Usage

```bash
cp terraform.tfvars.example terraform.tfvars   # gitignored; fill in tenancy values
tofu init
tofu fmt -recursive -check
tofu validate
tofu plan      # expect: Plan: 6 to add, 0 to change, 0 to destroy
```

`tofu apply` belongs to the deployment stage, not to this one. The configuration
has been validated and planned against a real tenancy; no resource was created.

## What is deliberately **not** in state

- the scanner's `.env` values, webhook URLs or API tokens — created on the host;
- the SSH private key — only the public key enters instance metadata;
- any application secret. `terraform.tfstate` holds resource identifiers, and
  nothing here puts a credential into a resource attribute.

Cloud-init is rendered from a template that receives only the project name, the
scanner port, the install directory and the repository URL. Instance user-data
is readable from the metadata service by anything on the host, so treating it as
a safe channel for secrets would be a design error.

## Porting to AWS

| OCI | AWS |
| --- | --- |
| `oci_core_vcn` | `aws_vpc` |
| `oci_core_internet_gateway` | `aws_internet_gateway` |
| `oci_core_route_table` | `aws_route_table` + `aws_route` |
| `oci_core_security_list` | `aws_security_group` + `aws_vpc_security_group_ingress_rule` |
| `oci_core_subnet` | `aws_subnet` |
| `oci_core_instance` + `shape_config` | `aws_instance` (`t4g.small`, ARM, free tier) |
| `metadata.user_data` (base64) | `user_data` (plain) |

Keep the same two ingress rules on the security group and the same module
outputs (`subnet_id`, `public_ip`). Nothing else changes.

## Porting to GCP

| OCI | GCP |
| --- | --- |
| `oci_core_vcn` | `google_compute_network` |
| `oci_core_internet_gateway` / route table | implicit default route |
| `oci_core_security_list` | `google_compute_firewall` (two rules, same CIDRs) |
| `oci_core_subnet` | `google_compute_subnetwork` |
| `oci_core_instance` | `google_compute_instance` (`e2-micro`, free tier in `us-central1`) |
| `metadata.user_data` | `metadata_startup_script` (drop the base64) |

GCP needs `network_interface { access_config {} }` for the public IP; the
`ingress_ports` output maps to the firewall `allow` blocks.

## Cost

Everything sits inside the OCI Always Free envelope: A1.Flex 1 OCPU / 6 GB,
50 GB boot volume (200 GB free across the tenancy) and egress far below the
10 TB/month allowance. Effective monthly cost: **$0**.
