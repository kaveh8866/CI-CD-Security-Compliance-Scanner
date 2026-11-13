output "vcn_id" {
  description = "OCID of the VCN."
  value       = oci_core_vcn.this.id
}

output "subnet_id" {
  description = "OCID of the public subnet."
  value       = oci_core_subnet.public.id
}

output "security_list_id" {
  description = "OCID of the security list (ingress: 22 and scanner_port only)."
  value       = oci_core_security_list.public.id
}

output "internet_gateway_id" {
  description = "OCID of the internet gateway."
  value       = oci_core_internet_gateway.this.id
}

output "route_table_id" {
  description = "OCID of the public route table."
  value       = oci_core_route_table.public.id
}

# Read back from the created security list, not from the input variables, so an
# operator sees the host's actual exposed surface rather than the intent.
output "ingress_ports" {
  description = "Inbound TCP ports the security list actually allows."
  value       = [for rule in oci_core_security_list.public.ingress_security_rules : rule.tcp_options[0].min]
}

output "ingress_sources" {
  description = "Source CIDRs paired with the open ports, for an explicit exposure review."
  value       = [for rule in oci_core_security_list.public.ingress_security_rules : "${rule.tcp_options[0].min}/tcp <- ${rule.source}"]
}

output "egress_cidrs" {
  description = "Destinations the security list actually permits outbound traffic to."
  value       = [for rule in oci_core_security_list.public.egress_security_rules : rule.destination]
}
