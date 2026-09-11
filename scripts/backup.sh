#!/usr/bin/env sh
set -eu

: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${BACKUP_BUCKET:?BACKUP_BUCKET is required}"

backup_file="/tmp/eolwatch-$(date -u +%Y%m%dT%H%M%SZ).sql.gz"
docker compose -f docker-compose.prod.yml exec -T db pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" | gzip > "$backup_file"
aws s3 cp "$backup_file" "s3://$BACKUP_BUCKET/postgres/$(basename "$backup_file")" --sse AES256
rm -f "$backup_file"
