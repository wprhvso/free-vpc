output "device_policy_id" {
  value = cloudflare_device_settings_policy.free_vpc_mesh.id
}

output "split_tunnel_id" {
  value = cloudflare_split_tunnel.mesh_include.id
}

output "enrollment_policy_id" {
  value = cloudflare_zero_trust_access_policy.device_enrollment.id
}

output "warp_app_id" {
  value = cloudflare_zero_trust_access_application.warp_enrollment.id
}

output "worker_url" {
  value = "https://free-vpc-orchestrator.wprhvso.workers.dev"
}

output "d1_database_id" {
  value = cloudflare_d1_database.free_vpc_db.id
}

output "d1_database_name" {
  value = cloudflare_d1_database.free_vpc_db.name
}
