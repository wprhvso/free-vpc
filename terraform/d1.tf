resource "cloudflare_d1_database" "free_vpc_db" {
  account_id = var.cloudflare_account_id
  name       = "free-vpc-db"
}
