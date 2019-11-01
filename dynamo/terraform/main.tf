resource "aws_dynamodb_table" "ja3-table" {
  name = "JA3Fingerprints"
  billing_mode = "PROVISIONED"
  read_capacity = 5
  write_capacity = 5
  hash_key = "ja3"

  attribute {
    name = "ja3"
    type = "S"

  }

  tags = {
    Name = "JA3-Fingerprint-Table"
    Environment = "ja3-production"
  }

  ttl {
    attribute_name = "TimeToExist"
    enabled = true
  }
}

output "table-arn" {
  value = aws_dynamodb_table.ja3-table.arn
}
