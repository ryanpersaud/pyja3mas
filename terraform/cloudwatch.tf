# resource "aws_iam_role_policy_attachment" "ja3-cloudwatch" {
#   role = aws_iam_role.ja3.name
#   policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
# }

data "aws_iam_policy_document" "ja3-cloudwatch-policy-document" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams"
    ]
    resources = [
      "arn:aws:logs:*:*:*"
    ]
  }
}

resource "aws_iam_policy" "ja3-cloudwatch-policy" {
  name = "ja3-cloudwatch-policy"
  path = "/"
  description = "Cloudwatch policy for ja3 server"
  policy = data.aws_iam_policy_document.ja3-cloudwatch-policy-document.json
}

resource "aws_iam_role_policy_attachment" "ja3-cloudwatch" {
  role = aws_iam_role.ja3.name
  policy_arn = aws_iam_policy.ja3-cloudwatch-policy.arn
}
