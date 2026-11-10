#!/usr/bin/env bash
# Prints a .env with fresh random secrets, based on .env.example.
set -euo pipefail
cd "$(dirname "$0")/.."
hex() { openssl rand -hex 32; }
fernet() { openssl rand -base64 32 | tr '+/' '-_'; }
sed -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(hex)|" \
    -e "s|^VMS_SECRET_KEY=.*|VMS_SECRET_KEY=$(hex)|" \
    -e "s|^VMS_FERNET_KEY=.*|VMS_FERNET_KEY=$(fernet)|" \
    -e "s|^VMS_INTERNAL_TOKEN=.*|VMS_INTERNAL_TOKEN=$(hex)|" \
    -e "s|^VMS_MEDIA_KEY=.*|VMS_MEDIA_KEY=$(openssl rand -base64 32)|" .env.example
