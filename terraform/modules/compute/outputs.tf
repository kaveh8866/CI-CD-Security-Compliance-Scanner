output "instance_id" {
  description = "OCID of the compute instance."
  value       = oci_core_instance.this.id
}

output "public_ip" {
  description = "Public IPv4 address of the primary VNIC."
  value       = data.oci_core_vnic.primary.public_ip_address
}

output "private_ip" {
  description = "Private IPv4 address of the primary VNIC."
  value       = data.oci_core_vnic.primary.private_ip_address
}

output "availability_domain" {
  description = "Availability domain the instance landed in."
  value       = local.availability_domain
}

output "image_id" {
  description = "Image actually used (resolved or pinned)."
  value       = local.resolved_image_id
}

output "shape" {
  description = "Shape the instance was created with."
  value       = oci_core_instance.this.shape
}

output "sizing" {
  description = "Effective flex sizing, or null for fixed shapes."
  value       = try(oci_core_instance.this.shape_config[0], null)
}

output "is_publicly_reachable" {
  description = "Whether the primary VNIC gets a public IP (required for SSH administration)."
  value       = oci_core_instance.this.create_vnic_details[0].assign_public_ip
}
