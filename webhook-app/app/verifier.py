import os
import subprocess
import redis

REDIS_HOST = os.getenv("REDIS_HOST", "redis-svc")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
COSIGN_PUB_KEY = os.getenv("COSIGN_PUB_KEY", "/etc/cosign/cosign.pub")
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "600"))

redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    socket_connect_timeout=1,
    socket_timeout=1,
    decode_responses=True,
)

def verify_image(image_name: str) -> tuple[bool, str, bool]:
    """
    Verifies a container image's cryptographic signature using Sigstore Cosign,
    with Redis caching to minimize registry round-trips.

    Returns:
        tuple: (is_valid: bool, message: str, cache_hit: bool)
    """
    cache_key = f"verified:{image_name}"

    # 1. Check Redis cache first
    try:
        cached = redis_client.get(cache_key)
        if cached == "1":
            return True, "Image signature verified from Redis cache", True
    except redis.RedisError as exc:
        print(f"Redis cache lookup failed (falling back to Cosign): {exc}")

    # 2. Run Cosign with writable HOME=/tmp and local public key verification
    env = os.environ.copy()
    env["HOME"] = "/tmp"
    env["SIGSTORE_ROOT_FILE"] = "/tmp/.sigstore"

    try:
        result = subprocess.run(
            [
                "cosign",
                "verify",
                "--key",
                COSIGN_PUB_KEY,
                "--insecure-ignore-tlog=true",
                image_name,
            ],
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return False, f"Cosign verification timed out for {image_name}", False
    except FileNotFoundError:
        return False, "Cosign binary not found inside admission container", False

    # 3. Save to cache if valid
    if result.returncode == 0:
        try:
            redis_client.setex(cache_key, CACHE_TTL_SECONDS, "1")
        except redis.RedisError:
            pass
        return True, "Cryptographic signature verified via Cosign", False

    if result.stderr:
        error_detail = result.stderr.strip().splitlines()[-1]
    else:
        error_detail = "No matching signature"
    return False, f"Untrusted image ({image_name}): {error_detail}", False
