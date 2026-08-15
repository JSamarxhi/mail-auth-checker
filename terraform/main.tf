terraform {
  required_version = ">= 1.9"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
  backend "azurerm" {
    resource_group_name  = "rg-tfstate"
    storage_account_name = "sttfstatejsamarxhi"
    container_name       = "tfstate"
    key                  = "mail-auth-checker.tfstate"
  }
}

provider "azurerm" {
  features {}
}

variable "prefix" {
  description = "Name prefix applied to every resource, so they group together and don't collide."
  type        = string
  default     = "mailcheck"
}

variable "container_image" {
  description = "Fully qualified container image to deploy."
  type        = string
  default     = "ghcr.io/jsamarxhi/mail-auth-checker:0.1"
}

variable "target_port" {
  description = "Port the container listens on. Must match EXPOSE/uvicorn in the Dockerfile."
  type        = number
  default     = 8000
}

resource "azurerm_resource_group" "main" {
  name     = "rg-${var.prefix}"
  location = "eastus"
}

data "azurerm_container_app_environment" "shared" {
  name                = "cae-platform"
  resource_group_name = "rg-platform"
}

resource "azurerm_container_app" "main" {
  name                         = "ca-${var.prefix}"
  resource_group_name          = azurerm_resource_group.main.name
  container_app_environment_id = data.azurerm_container_app_environment.shared.id

  revision_mode = "Single"

  template {
    # Scale to zero when idle. This is the setting that keeps cost at zero:
    # no replicas running means no vCPU-seconds billed.
    min_replicas = 0
    max_replicas = 1

    container {
      name   = var.prefix
      image  = var.container_image
      cpu    = 0.25 # valid CPU/memory pairs are fixed; 0.25 pairs with 0.5Gi
      memory = "0.5Gi"
    }
  }

  ingress {
    external_enabled = true            # reachable from the public internet
    target_port      = var.target_port # must match what the container listens on
    transport        = "auto"

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }
}

output "app_url" {
  description = "Public URL of the running service."
  value       = "https://${azurerm_container_app.main.ingress[0].fqdn}"
}

output "health_url" {
  description = "Health endpoint, for a quick post-deploy check."
  value       = "https://${azurerm_container_app.main.ingress[0].fqdn}/health"
}

output "docs_url" {
  description = "Interactive API documentation."
  value       = "https://${azurerm_container_app.main.ingress[0].fqdn}/docs"
}

output "resource_group_name" {
  description = "Resource group holding every resource in this configuration."
  value       = azurerm_resource_group.main.name
}
