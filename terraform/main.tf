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
    Environment = "testing"
  }
}

# resource "aws_dynamodb_table_item" "browser-info" {
#   table_name = aws_dynamodb_table.ja3-table.name
#   hash_key = aws_dynamodb_table.ja3-table.hash_key

#   item = <<ITEM
#   {
#     "ja3": {"S": "12345"},
#     "browser": {"L": [ {"L": [{"S": "testing"}, {"S": "testing2"}]} ] }
#   }
#   ITEM
# }
