variable "cloudflare_account_id" {
  type        = string
  description = "Cloudflare Account ID"
  default     = ""
}

variable "cloudflare_zone_id" {
  type        = string
  description = "Cloudflare Zone ID"
  default     = ""
}

variable "cluster_domain" {
  type        = string
  description = "Base domain for mesh tunnels (e.g. unsafie.com)"
  default     = "unsafie.com"
}

variable "cloudflare_api_token" {
  type        = string
  description = "Cloudflare API Token"
  sensitive   = true
  default     = ""
}

variable "github_repository" {
  type        = string
  description = "GitHub repository (owner/repo)"
  default     = "wprhvso/free-vpc"
}
