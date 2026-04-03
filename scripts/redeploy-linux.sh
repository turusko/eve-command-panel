#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

IMAGE_NAME="${IMAGE_NAME:-eve-esi-dashboard}"
CONTAINER_NAME="${CONTAINER_NAME:-eve-esi-dashboard}"
APP_PORT="${APP_PORT:-5000}"
DATA_DIR="${DATA_DIR:-${PROJECT_ROOT}/data}"
ENV_FILE="${ENV_FILE:-${PROJECT_ROOT}/.env}"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "Missing env file: ${ENV_FILE}" >&2
  exit 1
fi

mkdir -p "${DATA_DIR}"

echo "Stopping existing container if it exists..."
docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

echo "Building image ${IMAGE_NAME}..."
docker build -t "${IMAGE_NAME}" "${PROJECT_ROOT}"

echo "Starting container ${CONTAINER_NAME}..."
docker run -d \
  --name "${CONTAINER_NAME}" \
  --restart unless-stopped \
  -p "${APP_PORT}:5000" \
  --env-file "${ENV_FILE}" \
  -e DATABASE_PATH=/data/eve_dashboard.db \
  -e LOG_PATH=/data/eve_dashboard.log \
  -v "${DATA_DIR}:/data" \
  "${IMAGE_NAME}"

echo "Done."
echo "Container: ${CONTAINER_NAME}"
echo "Image: ${IMAGE_NAME}"
echo "Data dir: ${DATA_DIR}"
echo "Logs: ${DATA_DIR}/eve_dashboard.log"
