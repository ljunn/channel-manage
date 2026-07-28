#!/usr/bin/env sh
set -eu

INSTALL_DIR=${CHANNEL_MANAGE_DIR:-/opt/channel-manage}
REPOSITORY=${CHANNEL_MANAGE_REPO:-ljunn/channel-manage}
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

curl -fsSL "https://raw.githubusercontent.com/${REPOSITORY}/main/deploy/docker-compose.yml" -o docker-compose.yml
curl -fsSL "https://raw.githubusercontent.com/${REPOSITORY}/main/deploy/update.sh" -o update.sh
chmod 755 update.sh
if [ ! -f .env ]; then
  DB_PASSWORD=$(openssl rand -hex 24)
  JWT_SECRET=$(openssl rand -hex 32)
  ADMIN_PASSWORD=$(openssl rand -base64 18 | tr -d '\n')
  cat > .env <<EOF
APP_PORT=4473
ADMIN_EMAIL=admin@channel.local
ADMIN_PASSWORD=${ADMIN_PASSWORD}
JWT_SECRET=${JWT_SECRET}
POSTGRES_USER=channel_manage
POSTGRES_PASSWORD=${DB_PASSWORD}
POSTGRES_DB=channel_manage
CHANNEL_MANAGE_IMAGE=ghcr.io/${REPOSITORY}:latest
TZ=Asia/Shanghai
EOF
  chmod 600 .env
  printf '初始管理员: admin@channel.local\n初始密码: %s\n' "$ADMIN_PASSWORD"
fi
docker compose pull
docker compose up -d
