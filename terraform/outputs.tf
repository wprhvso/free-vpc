output "device_policy_id" {
  value = cloudflare_device_settings_policy.free_vpc_mesh.id
}

output "split_tunnel_id" {
  value = cloudflare_split_tunnel.mesh_include.id
}
