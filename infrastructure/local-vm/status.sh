#!/usr/bin/env bash
set -euo pipefail

for vm in eolwatch-controller eolwatch-target-01 eolwatch-target-02; do
  VBoxManage showvminfo "$vm" --machinereadable 2>/dev/null | awk -F= -v vm="$vm" '$1 == "VMState" {gsub(/"/, "", $2); print vm ": " $2}' || echo "$vm: 없음"
done

if curl --fail --silent --max-time 5 http://127.0.0.1:18080/health | python3 -c 'import json, sys; sys.exit(0 if json.load(sys.stdin).get("status") == "ok" else 1)'; then
  echo
  echo "웹/API 정상: http://127.0.0.1:18080"
else
  echo "웹/API 응답 없음"
  exit 1
fi
