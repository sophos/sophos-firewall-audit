aws cloudformation create-stack \
--stack-name firewall-audit-user-role \
--template-body file://aws_user.yaml \
--capabilities CAPABILITY_NAMED_IAM