#!/usr/bin/env bash
# Configure .env for Cyber Threat Monitoring System (macOS compatible)
# Usage: bash scripts/config_env.sh

set -euo pipefail

# Move to project root (directory of this script is scripts/)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}/.."
cd "$PROJECT_ROOT"

ENV_FILE=".env"

# Detect sed in-place flag for macOS vs GNU
if [[ "$(uname)" == "Darwin" ]]; then
  SED_INPLACE=("sed" "-i" "")
else
  SED_INPLACE=("sed" "-i")
fi

ensure_env_file() {
  if [[ ! -f "$ENV_FILE" ]]; then
    echo "Creating $ENV_FILE ..."
    touch "$ENV_FILE"
  fi
}

# Set or update KEY=VALUE in .env
set_kv() {
  local key="$1"
  local value="$2"
  if grep -qE "^${key}=" "$ENV_FILE"; then
    "${SED_INPLACE[@]}" "s#^${key}=.*#${key}=${value}#" "$ENV_FILE"
  else
    printf "%s=%s\n" "$key" "$value" >> "$ENV_FILE"
  fi
}

# Generate a random secret (hex)
random_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  elif command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
  else
    # Fallback (less secure)
    date +%s | shasum | awk '{print $1}'
  fi
}

# Get existing value or empty
get_existing() {
  local key="$1"
  local val
  val=$(grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | head -n1 | cut -d= -f2- || true)
  echo "$val"
}

main() {
  ensure_env_file

  echo "Configuring environment in $ENV_FILE ..."

  # Required secrets
  local existing_secret existing_jwt
  existing_secret=$(get_existing SECRET_KEY)
  existing_jwt=$(get_existing JWT_SECRET_KEY)

  local secret_key jwt_secret
  secret_key=${existing_secret:-}
  jwt_secret=${existing_jwt:-}

  if [[ -z "${secret_key}" ]]; then
    secret_key=$(random_secret)
  fi
  if [[ -z "${jwt_secret}" ]]; then
    jwt_secret=$(random_secret)
  fi

  set_kv SECRET_KEY "$secret_key"
  set_kv JWT_SECRET_KEY "$jwt_secret"

  # API settings
  set_kv API_HOST "0.0.0.0"
  set_kv API_PORT "8001"
  set_kv DEBUG "true"

  # Databases
  set_kv MONGODB_URL "mongodb://admin:secure_mongo_password@localhost:27017/threat_monitoring?authSource=admin"
  set_kv MONGODB_DATABASE "threat_monitoring"
  set_kv ELASTICSEARCH_URL "http://localhost:9200"

  # TOR (set false for surface web testing)
  set_kv USE_TOR_PROXY "false"

  echo "✅ .env configured. Current values:"
  echo "----------------------------------"
  grep -E '^(SECRET_KEY|JWT_SECRET_KEY|API_HOST|API_PORT|DEBUG|MONGODB_URL|MONGODB_DATABASE|ELASTICSEARCH_URL|USE_TOR_PROXY)=' "$ENV_FILE" | sed -E 's/(SECRET_KEY|JWT_SECRET_KEY)=.*/\1=***hidden*** /'
  echo "----------------------------------"
  echo "Next steps:"
  echo "1) Start services:     docker-compose up -d"
  echo "2) Activate venv:      source venv/bin/activate  (or create: python3 -m venv venv)"
  echo "3) Install deps:       pip install -r requirements.txt"
  echo "4) Run API:            uvicorn ctms.api.main:app --host 0.0.0.0 --port 8001 --reload"
  echo "5) Run dashboard:      streamlit run ctms/dashboard/main_dashboard.py"
}

main "$@"