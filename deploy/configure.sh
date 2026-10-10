#!/usr/bin/env bash
# Adds the secrets a new server needs and opens the dashboard behind a password.
# Run on the server:  sudo bash /opt/phishwarden/deploy/configure.sh
set -euo pipefail

APP=/opt/phishwarden

read -rsp "Gemini API key: " key
echo
sed -i "s#^GEMINI_API_KEY=.*#GEMINI_API_KEY=$key#" "$APP/.env"

read -rp "Dashboard username [judge]: " user
user=${user:-judge}
echo "Choose the dashboard password:"
hash=$(caddy hash-password)

cat > /etc/caddy/Caddyfile <<EOF
:80 {
	basicauth {
		$user $hash
	}
	reverse_proxy 127.0.0.1:8600
}
:8081 {
	reverse_proxy 127.0.0.1:8080
}
EOF
systemctl restart caddy phishwarden-web
echo "Done. The dashboard is open on port 80 for user '$user'."
