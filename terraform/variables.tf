variable "cloudflare_account_id" {
  type    = string
  default = "39f6858f9b5865652ac69c506ec4736c"
}

variable "cloudflare_zone_id" {
  type    = string
  default = "8fdf0e75be2ee4a86d28f9662b258e1b"
}

variable "cluster_domain" {
  type    = string
  default = "unsafie.com"
}

variable "cloudflare_api_token" {
  type      = string
  sensitive = true
  default   = ""
}

variable "team_name" {
  type    = string
  default = "shy-resonance-71c0"
}

variable "github_repository" {
  type    = string
  default = "wprhvso/free-vpc"
}

variable "github_token" {
  type      = string
  sensitive = true
  default   = ""
}
