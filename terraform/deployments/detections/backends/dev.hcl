bucket         = "acme-tfstate-security"
key            = "elastic-dac/dev/terraform.tfstate"
region         = "ap-south-1"
dynamodb_table = "acme-tfstate-locks"
encrypt        = true
