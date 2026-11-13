# OCI compute module — one Always Free eligible instance running the scanner host.
#
# PORTABILITY — the instance resource on the other free tiers:
#
#   | OCI (here)                             | AWS                                     | GCP                                     |
#   | -------------------------------------- | --------------------------------------- | --------------------------------------- |
#   | oci_core_instance                      | aws_instance                            | google_compute_instance                 |
#   | shape VM.Standard.A1.Flex (ARM, free)  | t4g.small / t3.micro (free tier)        | e2-micro / e2-small (free tier)         |
#   | shape_config { ocpus, memory_in_gbs }  | instance_type                           | machine_type                            |
#   | create_vnic_details                    | subnet_id + associate_public_ip_address | network_interface { access_config { } } |
#   | metadata.user_data (base64 cloud-init) | user_data                               | metadata_startup_script                 |
#
# `availability_domain` maps to an AWS AZ or a GCP zone; every other input is
# provider-neutral, so the module interface survives the port unchanged.
#
# SIZING: the scanner container is capped at 128 MB / 0.25 CPU and measured at
# ~19 MB idle, ~25 MB during a scan. 1 OCPU / 6 GB A1.Flex leaves headroom for
# Docker, an image pull and a full repository scan while staying inside the
# Always Free envelope (2 OCPU / 12 GB across all A1 instances today).

locals {
  is_flex_shape = can(regex("Flex$", var.instance_shape))

  # A specified AD wins; otherwise the first AD in the region (the Always Free
  # flow). A1 capacity is frequently exhausted in AD-1 — pin AD-2 in tfvars when
  # the first apply reports "Out of host capacity".
  availability_domain = coalesce(
    var.availability_domain,
    data.oci_identity_availability_domains.ads.availability_domains[0].name
  )

  # Only query images when the caller did not pin one — this keeps `plan` working
  # in regions where the image list is not readable but an OCID is known.
  resolve_image     = var.image_id == null
  resolved_image_id = local.resolve_image ? data.oci_core_images.ubuntu[0].images[0].id : var.image_id
}

data "oci_identity_availability_domains" "ads" {
  # Availability domains are tenancy-scoped.
  compartment_id = var.tenancy_ocid
}

data "oci_core_images" "ubuntu" {
  count = local.resolve_image ? 1 : 0

  compartment_id           = var.compartment_id
  operating_system         = var.image_operating_system
  operating_system_version = var.image_os_version
  # Filtering by shape is what selects the aarch64 build for A1 shapes.
  shape      = var.instance_shape
  sort_by    = "TIMECREATED"
  sort_order = "DESC"
}

resource "oci_core_instance" "this" {
  compartment_id      = var.compartment_id
  availability_domain = local.availability_domain
  display_name        = "${var.name_prefix}-vm"
  shape               = var.instance_shape
  freeform_tags       = var.freeform_tags

  # Flex shapes (A1.Flex, E4.Flex) require shape_config; fixed shapes reject it.
  dynamic "shape_config" {
    for_each = local.is_flex_shape ? [1] : []

    content {
      ocpus         = var.instance_ocpus
      memory_in_gbs = var.instance_memory_gbs
    }
  }

  source_details {
    source_type             = "image"
    source_id               = local.resolved_image_id
    boot_volume_size_in_gbs = var.boot_volume_size_gbs
  }

  create_vnic_details {
    subnet_id        = var.subnet_id
    assign_public_ip = true
    display_name     = "${var.name_prefix}-vnic"
    hostname_label   = var.hostname_label
  }

  metadata = {
    ssh_authorized_keys = var.ssh_public_key
    user_data           = var.user_data
  }

  # Ubuntu images take a few minutes on first boot; give cloud-init time to
  # finish before the instance is considered created.
  timeouts {
    create = "20m"
  }
}

# Public IP is read from the VNIC rather than the deprecated instance attribute,
# so the output stays correct on current provider versions.
data "oci_core_vnic_attachments" "this" {
  compartment_id = var.compartment_id
  instance_id    = oci_core_instance.this.id
}

data "oci_core_vnic" "primary" {
  vnic_id = data.oci_core_vnic_attachments.this.vnic_attachments[0].vnic_id
}
