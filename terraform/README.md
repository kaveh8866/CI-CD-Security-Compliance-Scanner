# OCI infrastructure (reserved)

Stage 2 fills this directory with OpenTofu that provisions the scanner on an
OCI Always Free `VM.Standard.A1.Flex` instance (1 OCPU / 6–12 GB, depending on
current Always Free allowances), a VCN with a public subnet for SSH, and an
ingress rule for the scanner port restricted to the operator's address.

Nothing here is applied yet: Stage 1 deliberately ships no cloud resources, so a
fresh checkout cannot create or bill anything.

Planned layout, mirroring the other CloudGuard projects:

```
terraform/
├── main.tf                 module wiring
├── provider.tf             OCI provider + region
├── variables.tf            tenancy, compartment, shape, CIDRs
├── outputs.tf              public IP, instance OCID, SSH command
├── terraform.tfvars.example
└── modules/
    ├── network/            VCN, subnet, internet gateway, route table, security list
    └── compute/            instance, cloud-init, boot volume
```

Ground rules for that stage:

- The scanner image is pulled or built by cloud-init; the API listens on the
  private interface and is reachable only through an SSH tunnel.
- No secret is written to Terraform state or instance metadata. Policy files are
  baked into the image; the scan workspace is a checkout, not a credential store.
- `tofu destroy` is destructive and only runs on explicit operator request.
