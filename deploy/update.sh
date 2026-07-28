#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"
mkdir -p backups
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' | gzip > "backups/channel-manage-${STAMP}.sql.gz"
docker compose pull
docker compose up -d --remove-orphans
docker image prune -f >/dev/null
