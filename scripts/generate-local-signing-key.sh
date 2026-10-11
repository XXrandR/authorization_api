#!/usr/bin/env sh
set -eu

key_store="${1:-$HOME/.conecta/authorization-server.p12}"
password="${AUTHORIZATION_KEY_STORE_PASSWORD:?Set AUTHORIZATION_KEY_STORE_PASSWORD first}"

mkdir -p "$(dirname "$key_store")"

keytool -genkeypair \
  -alias authorization-server \
  -keyalg RSA \
  -keysize 3072 \
  -validity 3650 \
  -dname 'CN=Conecta Authorization Server' \
  -storetype PKCS12 \
  -keystore "$key_store" \
  -storepass "$password" \
  -keypass "$password"

printf 'Created %s\n' "$key_store"
