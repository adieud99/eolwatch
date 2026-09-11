#!/usr/bin/env sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "사용법: $0 s3://버킷/postgres/백업.sql.gz" >&2
  exit 2
fi
: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${POSTGRES_DB:?POSTGRES_DB is required}"

restore_file="/tmp/eolwatch-restore.sql.gz"
aws s3 cp "$1" "$restore_file"
gzip -dc "$restore_file" | docker compose -f docker-compose.prod.yml exec -T db psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" "$POSTGRES_DB"
rm -f "$restore_file"
