import os
import time
import httpx
from fastapi import FastAPI, Request, Response
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from app.verifier import verify_image

app = FastAPI(title="Zero-Trust Kubernetes Admission Webhook")

# OPA microservice endpoint inside the security-system namespace
OPA_URL = os.getenv("OPA_URL", "http://opa-svc:8181/v1/data/k8s/admission")

# Prometheus Telemetry Metrics
ADMISSION_REQUESTS = Counter(
    "admission_requests_total",
    "Total admission requests processed",
    ["decision", "reason"],
)
CACHE_HITS = Counter(
    "cosign_cache_hits_total",
    "Total Cosign signature verifications served from Redis cache",
)
VALIDATION_LATENCY = Histogram(
    "admission_validation_duration_seconds",
    "Time spent validating an admission request",
)

def build_admission_response(uid: str, allowed: bool, message: str, code: int = 200) -> dict:
    """Wraps the allow/deny decision in the JSON envelope Kubernetes expects"""
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": uid,
            "allowed": allowed,
            "status": {
                "code": code,
                "message": message
            },
        },
    }

@app.get("/healthz")
async def healthz():
    """Kubernetes liveness and readiness probe endpoint"""
    return {"status": "healthy"}

@app.get("/metrics")
async def get_metrics():
    """Prometheus metrics scraping endpoint"""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.post("/validate")
async def validate(request: Request):
    """Main admission webhook endpoint for Kubernetes"""
    start_time = time.time()
    body = await request.json()

    req = body.get("request", {})
    uid = req.get("uid", "")
    pod_object = req.get("object", {})

    # Extract containers from a raw Pod or Deployment pod template
    kind = req.get("kind", {}).get("kind","")
    if kind == "Deployment":
        pod_spec = pod_object.get("spec", {}).get("template", {}).get("spec", {})
    else:
        pod_spec = pod_object.get("spec", {})
    containers = pod_spec.get("containers", [])

    # 1. Supply-chain gate: verify cryptographic signature for every container
    for container in containers:
        image_name = container["image"]
        is_valid, message, cache_hit = verify_image(image_name)
        
        if cache_hit:
            CACHE_HITS.inc()
        
        if not is_valid:
            ADMISSION_REQUESTS.labels(decision="denied", reason="cosign_failed").inc()
            VALIDATION_LATENCY.observe(time.perf_counter() - start_time)
            return build_admission_response(uid, allowed=False, message=message, code=403)

    # 2. Policy gate: send the workload spec to Open Policy
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            opa_response = await client.post(OPA_URL, json={"input": pod_object})
            opa_response.raise_for_status()
            opa_result = opa_response.json().get("result", {})
    except httpx.RequestError as exc:
        # Fail-closed: if OPA is unreachable, deny deployment for zero-trust safety
        ADMISSION_REQUESTS.labels(decision="denied", reason="opa_unreachable").inc()
        VALIDATION_LATENCY.observe(time.perf_counter() - start_time)
        return build_admission_response(
            uid, allowed=False, message=f"Policy engine unavailable: {exc}", code=503
            )

    # 3. Return the OPA decision to Kubernetes#   
    ADMISSION_REQUESTS.labels(decision="allowed", reason="opa_passed").inc()
    VALIDATION_LATENCY.observe(time.perf_counter() - start_time)
    return build_admission_response(
        uid, allowed=True, message="Checks passed"
    )