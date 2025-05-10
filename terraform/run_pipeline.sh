#!/bin/bash
set -euo pipefail
cd ../

echo "[INFO] Working directory changed to: $(pwd)"

# Clone repo
echo "[INFO] Cloning GitHub repository..."
export GH_TOKEN=$(gta write-pr it.netauto.firewall-audit-results)
git clone https://x-access-token:$GH_TOKEN@github.com/sophos-internal/it.netauto.firewall-audit-results.git it.netauto.firewall-audit-results

# Copy result files
./terraform/copyfiles.sh 'it.netauto.firewall-audit-results/index.html' './results_html_web/'
./terraform/copyfiles.sh 'it.netauto.firewall-audit-results/audit-results*' './results_html_web'
cp it.netauto.firewall-audit-results/audit_settings.yaml ./

# Install audit tool
echo "[INFO] Installing sophos_firewall_audit..."
gh release download v1.0.11 --repo github.com/sophos/sophos-firewall-audit
pip install sophos_firewall_audit-1.0.11-py3-none-any.whl

# Run audit
echo "[INFO] Running audit tool..."

sophosfirewallaudit -s audit_settings.yaml --use_nautobot -q nautobot_query/all_devices_query.gql --disable_verify --use_vault
mv results_html_web docker/

# Write SSL cert and key
# printf "%b" "$SSL_CERT" > ../docker/server.crt
# printf "%b" "$SSL_KEY" > ../docker/server.key
jq -r '.SSL_CERT' ./terraform/env0.env-vars.json | \
awk 'BEGIN {print "-----BEGIN CERTIFICATE-----"} 
     NR==1 {gsub(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----/, "")}
     {gsub(/ /, ""); for (i = 1; i <= length($0); i += 64) print substr($0, i, 64)} 
     END {print "-----END CERTIFICATE-----"}' > ./docker/server.crt

jq -r '.SSL_KEY' ./terraform/env0.env-vars.json | \
awk 'BEGIN {print "-----BEGIN PRIVATE KEY-----"} 
     NR==1 {gsub(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----/, "")}
     {gsub(/ /, ""); for (i = 1; i <= length($0); i += 64) print substr($0, i, 64)} 
     END {print "-----END PRIVATE KEY-----"}' > ./docker/server.key

echo "[INFO] setting up TLS for Docker..."
# Docker TLS setup
mkdir -p ~/.docker
export DOCKER_HOST='tcp://10.183.4.122:2375'
export DOCKER_TLS_VERIFY=1
# printf "%b" "$DOCKER_CA_CERT" > ~/.docker/ca.pem
jq -r '.DOCKER_CA_CERT' ./terraform/env0.env-vars.json | \
awk 'BEGIN {print "-----BEGIN CERTIFICATE-----"} 
     NR==1 {gsub(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----/, "")}
     {gsub(/ /, ""); for (i = 1; i <= length($0); i += 64) print substr($0, i, 64)} 
     END {print "-----END CERTIFICATE-----"}' > ~/.docker/ca.pem

# printf "%b" "$DOCKER_CLIENT_CERT" > ~/.docker/cert.pem
jq -r '.DOCKER_CLIENT_CERT' ./terraform/env0.env-vars.json | \
awk 'BEGIN {print "-----BEGIN CERTIFICATE-----"} 
     NR==1 {gsub(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----/, "")}
     {gsub(/ /, ""); for (i = 1; i <= length($0); i += 64) print substr($0, i, 64)} 
     END {print "-----END CERTIFICATE-----"}' > ~/.docker/cert.pem

# printf "%b" "$DOCKER_CLIENT_KEY" > ~/.docker/key.pem
jq -r '.DOCKER_CLIENT_KEY' ./terraform/env0.env-vars.json | \
awk 'BEGIN {print "-----BEGIN RSA PRIVATE KEY-----"} 
     NR==1 {gsub(/-----BEGIN RSA PRIVATE KEY-----|-----END RSA PRIVATE KEY-----/, "")}
     {gsub(/ /, ""); for (i = 1; i <= length($0); i += 64) print substr($0, i, 64)} 
     END {print "-----END RSA PRIVATE KEY-----"}' > ~/.docker/key.pem

# Assume AWS role
echo "[INFO] Assuming AWS role..."
assume_role_output=$(aws sts assume-role --role-arn $ROLE_ARN --role-session-name factory-runner-pipeline)
aws_access_key_id="$(echo "$assume_role_output" | jq -r '.Credentials.AccessKeyId')"
aws_secret_access_key="$(echo "$assume_role_output" | jq -r '.Credentials.SecretAccessKey')"
aws_session_token="$(echo "$assume_role_output" | jq -r '.Credentials.SessionToken')"

# Configure AWS CLI
mkdir -p ~/.aws
printf "%b" "[default]
aws_access_key_id = ${aws_access_key_id}
aws_secret_access_key = ${aws_secret_access_key}
aws_session_token = ${aws_session_token}
" > ~/.aws/credentials

unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY

aws sts get-caller-identity

# Build and push Docker image
echo "[INFO] Building and pushing Docker image..."
aws eks update-kubeconfig --region eu-west-1 --name SophosFactory
export REVISION=$(helm list --filter 'fwaudit' --output=json | jq -r '.[].revision')
export TAG=$(python -c "import os; print(int(os.environ['REVISION']) + 1)")
aws ecr get-login-password | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.eu-west-1.amazonaws.com
docker build -f ./docker/Dockerfile ./docker -t $AWS_ACCOUNT_ID.dkr.ecr.eu-west-1.amazonaws.com/fwaudit-results:$TAG
docker push $AWS_ACCOUNT_ID.dkr.ecr.eu-west-1.amazonaws.com/fwaudit-results:$TAG

# Deploy with Helm
echo "[INFO] Upgrading Helm release..."
helm upgrade fwaudit ./helm-chart -f ./helm-chart/values.yaml --set fwaudit.image.tag=$TAG

echo "[INFO] Copy and push results to GitHub..."
# Copy and push results to GitHub
cd it.netauto.firewall-audit-results
echo "[INFO] Working directory changed to: $(pwd)"
export SOURCE_DIR="../docker/results_html_web/*"
git checkout -b factory-pipeline-results
cp -r $SOURCE_DIR .

git config --global user.email "factory-it-admins@sophos.com"
git config --global user.name "Factory Pipeline"
git add .
git commit -m "audit results updated"
git push --set-upstream origin factory-pipeline-results

cd ../terraform
echo "[INFO] Working directory changed to: $(pwd)"
echo "[INFO] merging PR..."
# Merge PR and notify
python merge_pr.py

echo "[INFO] Sending email..."
python postaudit_web.py

echo "[INFO] Pipeline completed."
