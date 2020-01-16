data "aws_iam_policy_document" "cloudwatch_agent_policy_doc" {
  statement {
    effect = "Allow"
    principals {
      type = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "ja3_cloudwatch_agent" {
  name = "ja3-cloudwatch"
  assume_role_policy = data.aws_iam_policy_document.cloudwatch_agent_policy_doc.json
}

resource "aws_iam_role_policy_attachment" "cloudwatch_agent_server" {
  role = aws_iam_role.ja3_cloudwatch_agent.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}
