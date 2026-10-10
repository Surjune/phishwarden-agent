#!/usr/bin/env bash
# First-boot setup for an Ubuntu 24.04 EC2 instance, run as root from EC2 user data:
#
#   #!/bin/bash
#   git clone https://github.com/Surjune/phishwarden-agent.git /opt/phishwarden
#   bash /opt/phishwarden/deploy/setup.sh > /var/log/phishwarden-setup.log 2>&1
#
# Installs Docker, uv and Caddy; starts Mailpit, the AgntID runtime, the PhishWarden tool
# server and dashboard. Secrets are added afterwards with deploy/configure.sh.
set -euxo pipefail

APP=/opt/phishwarden
UV=/home/ubuntu/.local/bin/uv
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y ca-certificates curl caddy
curl -fsSL https://get.docker.com | sh
usermod -aG docker ubuntu
sudo -u ubuntu -H bash -c 'curl -LsSf https://astral.sh/uv/install.sh | sh'

chown -R ubuntu:ubuntu "$APP"
cd "$APP"
if [ ! -f .env ]; then
  sed -e 's#^AGNTID_TRIAGE_MCP_URL=.*#AGNTID_TRIAGE_MCP_URL=http://127.0.0.1:8082/mcp#' \
      -e 's#^AGNTID_RESPONSE_MCP_URL=.*#AGNTID_RESPONSE_MCP_URL=http://127.0.0.1:8082/mcp#' \
      .env.example > .env
  # The AgntID container reaches the tool server over the Docker bridge, so it listens
  # on all interfaces; the security group keeps port 8000 closed to the internet.
  echo "MCP_BIND_HOST=0.0.0.0" >> .env
  chown ubuntu:ubuntu .env
  chmod 600 .env
fi

docker compose up -d
sudo -u ubuntu -H bash -c "cd $APP && $UV sync"
until curl -sf http://127.0.0.1:8025/api/v1/info > /dev/null; do sleep 2; done
sudo -u ubuntu -H bash -c "cd $APP && $UV run python -m phishwarden.seed"

for svc in server web; do
  cat > "/etc/systemd/system/phishwarden-$svc.service" <<EOF
[Unit]
Description=PhishWarden $svc
After=network-online.target docker.service
Wants=network-online.target

[Service]
User=ubuntu
WorkingDirectory=$APP
ExecStart=$UV run --no-sync python -m phishwarden.$svc
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
done
systemctl daemon-reload
systemctl enable --now phishwarden-server phishwarden-web

# The dashboard stays closed until deploy/configure.sh sets a password. Port 8081 is the
# AgntID runtime's admin page, where the bootstrap token is entered; the security group
# limits it to the owner's IP.
cat > /etc/caddy/Caddyfile <<'EOF'
:80 {
	respond "PhishWarden is being set up." 503
}
:8081 {
	reverse_proxy 127.0.0.1:8080
}
EOF
systemctl restart caddy

# The AgntID intent parser downloads a ~900 MB model on first start and reports unhealthy
# until it finishes, which can fail the first `up`; keep retrying in the background.
curl -fsSL https://raw.githubusercontent.com/AGNTID-AI/agntid-python/main/docker-compose.yml \
  -o agntid-runtime/docker-compose.yml
nohup bash -c "cd $APP/agntid-runtime && for i in \$(seq 1 15); do docker compose up -d && break; sleep 60; done" \
  > /var/log/agntid-runtime-start.log 2>&1 &
