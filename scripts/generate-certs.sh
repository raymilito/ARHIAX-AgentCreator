#!/usr/bin/env bash
# generate-certs.sh — Genera la CA interna y certificados TLS por servicio
# Uso: bash scripts/generate-certs.sh
# Requiere: openssl
set -euo pipefail

CERTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/certs"
DAYS_CA=3650       # CA válida 10 años
DAYS_SVC=825       # Certificados de servicio válidos ~2 años (límite Apple/Chrome)
COUNTRY="US"
ORG="Sinergia Consulting Group"
CA_CN="ARHIAX Internal CA"

# Servicios que necesitan certificado (nombre = hostname Docker)
SERVICES=(
  "aim-service"
  "aut-service"
  "bbr-service"
  "creator-api"
  "evidence-store"
  "gateway"
  "hic-service"
)

mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ARHIAX — Generador de certificados TLS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── 1. Certificate Authority ──────────────────────────────────────────────────
echo "▶ Generando CA interna..."

openssl genrsa -out ca.key 4096 2>/dev/null

openssl req -new -x509 \
  -key ca.key \
  -out ca.crt \
  -days "$DAYS_CA" \
  -subj "/C=${COUNTRY}/O=${ORG}/CN=${CA_CN}" \
  -extensions v3_ca \
  2>/dev/null

echo "  ✓ ca.crt  (válido ${DAYS_CA} días)"
echo "  ✓ ca.key"

# ── 2. Certificado por servicio ───────────────────────────────────────────────
for SVC in "${SERVICES[@]}"; do
  echo ""
  echo "▶ Generando certificado para ${SVC}..."

  # Clave privada
  openssl genrsa -out "${SVC}.key" 2048 2>/dev/null

  # CSR con SAN — el SAN debe incluir el hostname Docker para que sea válido
  openssl req -new \
    -key "${SVC}.key" \
    -out "${SVC}.csr" \
    -subj "/C=${COUNTRY}/O=${ORG}/CN=${SVC}" \
    2>/dev/null

  # SAN extension file
  cat > "${SVC}.ext" <<EOF
[v3_req]
subjectAltName = @alt_names
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = ${SVC}
DNS.2 = localhost
IP.1  = 127.0.0.1
EOF

  # Firmar con la CA
  openssl x509 -req \
    -in "${SVC}.csr" \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out "${SVC}.crt" \
    -days "$DAYS_SVC" \
    -extensions v3_req \
    -extfile "${SVC}.ext" \
    2>/dev/null

  # Limpiar temporales
  rm -f "${SVC}.csr" "${SVC}.ext"

  echo "  ✓ ${SVC}.crt  (válido ${DAYS_SVC} días)"
  echo "  ✓ ${SVC}.key"
done

# ── 3. Permisos seguros ───────────────────────────────────────────────────────
echo ""
echo "▶ Ajustando permisos..."
chmod 600 ./*.key
chmod 644 ./*.crt
rm -f ca.srl

# ── 4. Verificación final ─────────────────────────────────────────────────────
echo ""
echo "▶ Verificando cadena de confianza..."
ALL_OK=true
for SVC in "${SERVICES[@]}"; do
  result=$(openssl verify -CAfile ca.crt "${SVC}.crt" 2>&1)
  if echo "$result" | grep -q "OK"; then
    echo "  ✓ ${SVC}.crt  OK"
  else
    echo "  ✗ ${SVC}.crt  FALLO: $result"
    ALL_OK=false
  fi
done

echo ""
if [ "$ALL_OK" = true ]; then
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  Certificados generados correctamente"
  echo "  Directorio: $CERTS_DIR"
  echo "  CA pública: certs/ca.crt"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
  echo "ERROR: Algunos certificados no pasaron la verificación"
  exit 1
fi
