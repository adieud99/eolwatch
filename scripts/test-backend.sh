#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
docker build --target test -t eolwatch-backend-test:local "$project_dir/backend"
docker run --rm --network none \
  --mount "type=bind,source=$project_dir/backend,target=/workspace/backend,readonly" \
  --mount "type=bind,source=$project_dir/scripts,target=/workspace/scripts,readonly" \
  --mount "type=bind,source=$project_dir/samples,target=/workspace/samples,readonly" \
  --mount "type=bind,source=$project_dir/pytest.ini,target=/workspace/pytest.ini,readonly" \
  eolwatch-backend-test:local
