# Outputs an operator (or the next agent) needs to reach the host. Everything
# here is public information: IPs, OCIDs and an exposure inventory — never a
# credential, a token or a webhook URL.

output "instance_public_ip" {
  description = "Public IPv4 address of the scanner host: SSH target, and the address the API is reachable at from scanner_allowed_cidr."
  value       = module.compute.public_ip
}

output "instance_private_ip" {
  description = "Private IPv4 address inside the VCN."
  value       = module.compute.private_ip
}

output "instance_id" {
  description = "OCID of the compute instance."
  value       = module.compute.instance_id
}

output "instance_shape" {
  description = "Shape actually used, including flex sizing in human-readable form."
  value       = "${var.instance_shape} (${var.instance_ocpus} OCPU / ${var.instance_memory_gbs} GB)"
}

output "availability_domain" {
  description = "Availability domain the instance landed in (pin it in tfvars when A1 capacity is tight)."
  value       = module.compute.availability_domain
}

output "scanner_url" {
  description = "Scanner API base URL once the container stack is deployed. Plain HTTP, reachable only from scanner_allowed_cidr or through an SSH tunnel."
  value       = "http://${module.compute.public_ip}:${var.scanner_port}"
}

output "vcn_id" {
  description = "OCID of the VCN."
  value       = module.network.vcn_id
}

output "subnet_id" {
  description = "OCID of the public subnet."
  value       = module.network.subnet_id
}

output "security_list_id" {
  description = "OCID of the security list."
  value       = module.network.security_list_id
}

output "ingress_ports" {
  description = "Inbound TCP ports actually opened: 22 plus scanner_port, and nothing else."
  value       = module.network.ingress_ports
}

output "ingress_exposure" {
  description = "Port/source pairs for an explicit exposure review. A world-open source here is a finding, not a setting."
  value       = module.network.ingress_sources
}

output "connection_endpoints" {
  description = "Copy-paste connection strings. The tunnel is the zero-exposure path: it needs no scanner ingress rule at all."
  value = {
    ssh        = "ssh ubuntu@${module.compute.public_ip}"
    api_direct = "http://${module.compute.public_ip}:${var.scanner_port}  (only from ${var.scanner_allowed_cidr})"
    api_tunnel = "ssh -N -L ${var.scanner_port}:127.0.0.1:${var.scanner_port} ubuntu@${module.compute.public_ip} && open http://127.0.0.1:${var.scanner_port}"
    logs       = "ssh ubuntu@${module.compute.public_ip} 'cd CI-CD-Security-Compliance-Scanner && docker compose --env-file .env -f docker/docker-compose.yml logs -f scanner'"
  }
}

output "deploy_next_step" {
  description = "What to run once apply finishes. Deliberately carries no credential: .env is created on the host."
  value       = <<-EOT
    1. ssh ubuntu@${module.compute.public_ip}
    2. git clone https://github.com/kaveh8866/CI-CD-Security-Compliance-Scanner.git
    3. cd CI-CD-Security-Compliance-Scanner && cp .env.example .env
       # edit .env locally on the host: bind the API to the private interface,
       # set SCANNER_FAIL_ON and any notification channel values
    4. docker compose --env-file .env -f docker/docker-compose.yml up -d --build
    5. curl -s http://127.0.0.1:${var.scanner_port}/healthz   # expect {"status":"ok",...}
  EOT
}
