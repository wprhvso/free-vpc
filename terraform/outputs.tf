output "portal_url" {
  value = "https://vm.unsafie.com"
}

output "d1_database_id" {
  value = cloudflare_d1_database.free_vpc_db.id
}

output "d1_database_name" {
  value = cloudflare_d1_database.free_vpc_db.name
}

output "cf_access_client_id" {
  value = cloudflare_zero_trust_access_service_token.orchestrator_token.client_id
}

output "cf_access_client_secret" {
  value     = cloudflare_zero_trust_access_service_token.orchestrator_token.client_secret
  sensitive = true
}
