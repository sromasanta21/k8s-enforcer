#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="security-system"
SERVICE="webhook-enforcer-svc"
CERT_DIR="./certs"

mkdir -p "${CERT_DIR}"

echo "[1/5] Generating internal Certificate Authority (CA)..."
openssl genrsa -out "${CERT_DIR}/ca.key" 2048
openssl req -x509 -new -nodes -key "${CERT_DIR}/ca.key" -subj "/CN=k8s-enforcer-ca" -days 365 -out "${CERT_DIR}/ca.crt"

echo "[2/5] Generating Webhook Server TLS Certificate with SANs..."
cat <<EOF > "${CERT_DIR}/csr.conf"
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${SERVICE}
DNS.2 = ${SERVICE}.${NAMESPACE}
DNS.3 = ${SERVICE}.${NAMESPACE}.svc
DNS.4 = ${SERVICE}.${NAMESPACE}.svc.cluster.local
EOF

openssl genrsa -out "${CERT_DIR}/tls.key" 2048
openssl req -new -key "${CERT_DIR}/tls.key" -subj "/CN=${SERVICE}.${NAMESPACE}.svc" -out "${CERT_DIR}/tls.csr" -config "${CERT_DIR}/csr.conf"
openssl x509 -req -in "${CERT_DIR}/tls.csr" -CA "${CERT_DIR}/ca.crt" -CAkey "${CERT_DIR}/ca.key" \
  -CAcreateserial -out "${CERT_DIR}/tls.crt" -days 365 -extensions v3_req -extfile "${CERT_DIR}/csr.conf"

echo "[3/5] Creating Kubernetes TLS Secret in '${NAMESPACE}'..."
kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret tls webhook-tls-certs \
  --cert="${CERT_DIR}/tls.crt" \
  --key="${CERT_DIR}/tls.key" \
  --namespace="${NAMESPACE}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "[4/5] Generating Sigstore Cosign Keypair & Secret..."
if ! command -v cosign &> /dev/null; then
  echo "Installing Cosign v3.1.4 CLI on master node..."
  curl -fsSL "https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64" -o /usr/local/bin/cosign
  chmod +x /usr/local/bin/cosign
fi

if [ ! -f "${CERT_DIR}/cosign.key" ]; then
  COSIGN_PASSWORD="" cosign generate-key-pair --output-key-prefix="${CERT_DIR}/cosign"
fi

kubectl create secret generic cosign-pub-key \
  --from-file=cosign.pub="${CERT_DIR}/cosign.pub" \
  --namespace="${NAMESPACE}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "[5/5] Injecting Base64 CA Bundle into 05-validating-webhook.yaml..."
CA_BUNDLE=$(base64 -w 0 < "${CERT_DIR}/ca.crt")
sed -i "s|\${CA_BUNDLE}|${CA_BUNDLE}|g" k8s-manifests/05-validating-webhook.yaml

echo "Done! TLS secrets, Cosign keys, and CA bundle are configured."