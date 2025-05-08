resource "null_resource" "run_python_script" {
  provisioner "local-exec" {
    command = <<EOT
      set -euo pipefail
      export GH_TOKEN=$(gta write-pr it.netauto.firewall-audit-results)
      git clone https://x-access-token:$GH_TOKEN@github.com/sophos-internal/it.netauto.firewall-audit-results.git it.netauto.firewall-audit-results
      ./copyfiles.sh 'it.netauto.firewall-audit-results/index.html' '../results_html_web/'
      ./copyfiles.sh 'it.netauto.firewall-audit-results/audit-results*' '../results_html_web'
      cp it.netauto.firewall-audit-results/audit_settings.yaml ../

      gh release download v1.0.11 --repo github.com/sophos/sophos-firewall-audit
      pip install sophos_firewall_audit-1.0.11-py3-none-any.whl

      sophosfirewallaudit -s ../audit_settings.yaml --use_nautobot -q ../nautobot_query/device_query.gql --disable_verify --use_vault
      mv results_html_web ../docker/

      # write ssl cert to sophos-firewall-audit/docker/server.crt
      cat > ../docker/server.crt <<EOF
      $SSL_CERT
      EOF

      # write ssl key to ../docker/server.key
      cat > ../docker/server.key <<EOF
      $SSL_KEY
      EOF

      assume_role_output=$(aws sts assume-role --role-arn $ROLE_ARN --role-session-name factory-runner-pipeline)

      # Extract access keys and session token from output
      aws_access_key_id=$(echo $assume_role_output | jq -r '.Credentials.AccessKeyId')
      aws_secret_access_key=$(echo $assume_role_output | jq -r '.Credentials.SecretAccessKey')
      aws_session_token=$(echo $assume_role_output | jq -r '.Credentials.SessionToken')

      # Write credentials file
      mkdir -p ~/.aws
      cat > ~/.aws/credentials <<EOF
      [default]
      aws_access_key_id = $aws_access_key_id
      aws_secret_access_key = $aws_secret_access_key
      aws_session_token = $aws_session_token
      EOF
  
      # Set up docker CLI for TLS
      export DOCKER_HOST='tcp://10.183.4.122:2375'
      export DOCKER_TLS_VERIFY=1

      cat > ~/.docker/ca.pem <<EOF
      $DOCKER_CA_CERT
      EOF
  
      cat > ~/.docker/cert.pem <<EOF
      $DOCKER_CLIENT_CERT
      EOF
  
      cat > ~/.docker/key.pem <<EOF
      $DOCKER_CLIENT_KEY
  
      # Build new container with updated results and push to ECR
      aws eks update-kubeconfig --region eu-west-1 --name SophosFactory
      export REVISION=$(helm list --filter 'fwaudit' --output=json | jq -r '.[].revision')
      export TAG=$(python -c "import os; print(int(os.environ['REVISION']) + 1)")
      aws ecr get-login-password | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.eu-west-1.amazonaws.com
      docker build -f ../docker/Dockerfile . -t $AWS_ACCOUNT_ID.dkr.ecr.eu-west-1.amazonaws.com/fwaudit-results:$TAG
      docker push $AWS_ACCOUNT_ID.dkr.ecr.eu-west-1.amazonaws.com/fwaudit-results:$TAG
  
      # Deploy new container with Helm
      helm upgrade fwaudit ../helm-chart -f ../helm-chart/values.yaml --set fwaudit.image.tag=$TAG 
  
      # Copy results 
      export SOURCE_DIR="../../docker/results_html_web/*"
      cd it.netauto.firewall-audit-results
      git checkout -b factory-pipeline-results
      cp -r $SOURCE_DIR .
  
      # Push results to Github
      git config --global user.email "factory-it-admins@sophos.com"
      git config --global user.name "Factory Pipeline"
      git add .
      git commit -m "audit results updated"
      git push --set-upstream origin factory-pipeline-results
  
      cd ..
  
      # Create and merge PR
      python merge_pr.py
  
      # Send notification
      python ../sophos_firewall_audit/postaudit_web.py

    EOT
    interpreter = ["/bin/bash", "-c"]
  }
    triggers = {
    always_run = timestamp()
  }
}