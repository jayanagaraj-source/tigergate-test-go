terraform {
  required_providers {
    # Deliberately old provider version for SCA scanner testing.
    aws = {
      source  = "hashicorp/aws"
      version = "3.0.0"
    }
  }
}
