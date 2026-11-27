# ------------------------------------------------------------------------------
# STEP 0: Pre-Flight Cluster & Cache Reset
# Purpose: Ensure no leftover test pods exist and flush the Redis digest cache
#          so Test 3 performs a cold cryptographic verification before Test 4
#          demonstrates a warm Redis cache hit.
# Expected Output:
#   - Pod deletions report "not found" (or delete leftover pods)
#   - redis-cli DEL returns "(integer) 1" or "(integer) 0"
#   - security-system pods (webhook-enforcer x2, opa, redis-cache) are Running
# ------------------------------------------------------------------------------
kubectl delete -f test-workloads/ --ignore-not-found
kubectl exec -n security-system deploy/redis-cache -- \
  redis-cli DEL "verified:sromasanta21/k8s-webhook-enforcer:v1.0.0"
kubectl get pods -n security-system -o wide


# ------------------------------------------------------------------------------
# TEST 1: Supply-Chain Provenance Gate (Unsigned Third-Party Image)
# Purpose: Attempt to deploy an official but unsigned image (nginx:1.27-alpine).
#          Proves Gate 1 (Sigstore Cosign) fails closed and short-circuits
#          before OPA policy evaluation is ever reached.
# Expected Output:
#   Error from server: error when creating "test-workloads/01-unsigned-pod.yaml":
#   admission webhook "enforcer.security-system.svc" denied the request:
#   Untrusted image (nginx:1.27-alpine): error during command execution: no signatures found
#   [NIST-SI-7] Requires integrity verification tools to detect unauthorized changes to defined software, firmware, and information
# ------------------------------------------------------------------------------
kubectl apply -f test-workloads/01-unsigned-pod.yaml


# ------------------------------------------------------------------------------
# TEST 2: Least-Privilege Posture Gate (Signed Image, Insecure Pod Spec)
# Purpose: Attempt to deploy your cryptographically signed image with root
#          privileges and default Linux capabilities. Proves separation of
#          concerns: valid provenance alone does not bypass OPA Rego controls.
#          (Note: This also verifies the signature at Gate 1 and populates Redis.)
# Expected Output:
#   Error from server: error when creating "test-workloads/02-root-privileged-pod.yaml":
#   admission webhook "enforcer.security-system.svc" denied the request:
#   [NIST-AC-6] Container 'insecure-app' must set securityContext.runAsNonRoot: true;
#   [NIST-CM-7] Container 'insecure-app' must drop ALL Linux capabilities (capabilities.drop: ["ALL"])
# ------------------------------------------------------------------------------
kubectl apply -f test-workloads/02-root-privileged-pod.yaml


# ------------------------------------------------------------------------------
# TEST 3: Compliant Workload Admission (Signed Image + Hardened SecurityContext)
# Purpose: Deploy a workload that satisfies both Gate 1 (Cosign signature) and
#          Gate 2 (non-root user, read-only root filesystem, drop ALL caps).
# Expected Output:
#   pod/test-compliant-signed-pod created
#   kubectl get pods shows test-compliant-signed-pod Running on k8s-worker-1
# ------------------------------------------------------------------------------
kubectl apply -f test-workloads/03-compliant-signed-pod.yaml
kubectl wait --for=condition=Ready pod/test-compliant-signed-pod --timeout=30s
kubectl get pods -o wide


# ------------------------------------------------------------------------------
# TEST 4: Redis Cache-Hit & Sub-Second Latency Verification
# Purpose: Confirm the verified image key is stored in Redis with a 600s TTL,
#          then deploy a second compliant workload using the same signed image.
#          Proves the webhook skips external Docker Hub + Cosign subprocess
#          execution and admits the pod in single-digit webhook milliseconds.
# Expected Output:
#   - redis-cli KEYS returns: verified:sromasanta21/k8s-webhook-enforcer:v1.0.0
#   - redis-cli TTL returns an integer <= 600 (e.g., 585)
#   - time kubectl apply completes in ~0.14s with "pod/test-redis-cache-hit-pod created"
# ------------------------------------------------------------------------------
kubectl exec -n security-system deploy/redis-cache -- redis-cli KEYS "verified:*"
kubectl exec -n security-system deploy/redis-cache -- \
  redis-cli TTL "verified:sromasanta21/k8s-webhook-enforcer:v1.0.0"

time kubectl apply -f test-workloads/04-redis-cache-hit-pod.yaml
kubectl get pods -o wide


# ------------------------------------------------------------------------------
# STEP 5: Prometheus Security & Performance Telemetry Audit
# Purpose: Scrape the HTTPS /metrics endpoint across both webhook-enforcer
#          replicas to verify audit counters for denied Cosign requests,
#          denied OPA requests, allowed admissions, and Redis cache hits.
# Expected Output (aggregated across both replicas):
#   admission_requests_total{decision="denied",reason="cosign_failed"} >= 1.0
#   admission_requests_total{decision="denied",reason="opa_failed"} >= 1.0
#   admission_requests_total{decision="allowed",reason="opa_passed"} >= 2.0
#   cosign_cache_hits_total >= 2.0
# ------------------------------------------------------------------------------
for pod in $(kubectl get pods -n security-system -l app=webhook-enforcer -o jsonpath='{.items[*].metadata.name}'); do
  echo "=== Telemetry from $pod ==="
  kubectl exec -n security-system "$pod" -- python3 -c \
    "import urllib.request, ssl; ctx = ssl._create_unverified_context(); print(urllib.request.urlopen('https://localhost:8443/metrics', context=ctx).read().decode())" \
    | grep -E "admission_requests_total|cosign_cache_hits_total"
done


# ------------------------------------------------------------------------------
# STEP 6: Demo Teardown
# Purpose: Remove admitted test pods so the default namespace returns to clean.
# Expected Output:
#   pod "test-compliant-signed-pod" deleted
#   pod "test-redis-cache-hit-pod" deleted
# ------------------------------------------------------------------------------
kubectl delete -f test-workloads/ --ignore-not-found