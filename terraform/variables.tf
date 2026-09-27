variable "cloudflare_account_id" {
  type    = string
  default = "39f6858f9b5865652ac69c506ec4736c"
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
