#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
RUNTIME_DIR="$SCRIPT_DIR/runtime"
SSH_KEY="$RUNTIME_DIR/id_ed25519"
ARCHIVE="$RUNTIME_DIR/eolwatch-source.tar.gz"
SSH=(ssh -i "$SSH_KEY" -p 12222 -o StrictHostKeyChecking=accept-new eolwatch@127.0.0.1)

[[ -f "$SSH_KEY" ]] || { echo "먼저 create-lab.sh를 실행하세요." >&2; exit 1; }

for attempt in {1..40}; do
  if "${SSH[@]}" cloud-init status --wait >/dev/null 2>&1; then break; fi
  if [[ "$attempt" == 40 ]]; then echo "controller VM의 cloud-init 완료를 확인하지 못했습니다." >&2; exit 1; fi
  sleep 5
done

COPYFILE_DISABLE=1 tar --no-xattrs -C "$PROJECT_DIR" \
  --exclude=.git --exclude=.venv --exclude=node_modules --exclude=frontend/dist \
  --exclude='infrastructure/local-vm/cache' --exclude='infrastructure/local-vm/runtime' \
  --exclude='infrastructure/terraform/.terraform' --exclude='*.tfstate*' --exclude='._*' --exclude=secrets \
  -czf "$ARCHIVE" .

scp -i "$SSH_KEY" -P 12222 -o StrictHostKeyChecking=accept-new "$ARCHIVE" eolwatch@127.0.0.1:/tmp/eolwatch-source.tar.gz
scp -i "$SSH_KEY" -P 12222 -o StrictHostKeyChecking=accept-new "$SSH_KEY" eolwatch@127.0.0.1:/tmp/eolwatch-collector-key

"${SSH[@]}" 'sudo mkdir -p /opt/eolwatch/secrets && sudo tar -xzf /tmp/eolwatch-source.tar.gz -C /opt/eolwatch && sudo find /opt/eolwatch -name "._*" -delete && sudo mv /tmp/eolwatch-collector-key /opt/eolwatch/secrets/eolwatch_ssh_key && sudo chown -R eolwatch:eolwatch /opt/eolwatch && chmod 600 /opt/eolwatch/secrets/eolwatch_ssh_key && for ip in 10.77.0.21 10.77.0.22; do ssh-keyscan -T 10 "$ip"; done > /opt/eolwatch/secrets/known_hosts && chmod 644 /opt/eolwatch/secrets/known_hosts && cd /opt/eolwatch && cat > .env <<EOF
JWT_SECRET=local-vm-demo-jwt-secret-change-after-demo
ADMIN_USERNAME=admin
ADMIN_PASSWORD=Eolwatch!2026
DEMO_TARGET_IPS=10.77.0.21,10.77.0.22
EOF
sudo docker compose up --build -d && sudo docker compose exec -T api python -m app.seed'

for attempt in {1..30}; do
  if curl --fail --silent --max-time 5 http://127.0.0.1:18080/health | python3 -c 'import json, sys; sys.exit(0 if json.load(sys.stdin).get("status") == "ok" else 1)'; then
    echo "EOLWatch 로컬 VM 배포 완료: http://127.0.0.1:18080"
    exit 0
  fi
  sleep 3
done
echo "컨테이너는 시작됐지만 상태 확인에 실패했습니다." >&2
exit 1
