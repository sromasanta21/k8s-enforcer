import os
import subprocess
import redis

# Configuration via environment variables (with Kubernetes defaults)
REDIS_HOST = os.getenv("REDIS_HOST", "redis-svc")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
COSIGN_PUB_KEY = os.getenv("COSIGN_PUB_KEY", "/etc/cosign/cosign.pub")
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "600"))

# Initialize Redis client with short socket timeouts so slow cache never stalls admission
redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    socket_connect_timeout=1,
    socket_timeout=1,
    decode_responses=True,
)

def verify_image(image_name: str) -> tuple[bool, str]:
    """
    Verifies a container image's cryptographic signature using Sigstore Cosign,
    with Redis caching to minimize registry round-trips.

    Returns:
        tuple: (is_valid: bool, message: str, cache_hit: bool)
    """
    cache_key = f"verified:{image_name}"


    #1. Check Redis cache first
    try:
        redis_client.get(cache_key)
        return True, "image signature verified from cache"
    except redis.Rediserror:
        print(redis.Rediserror)
    except subprocess.TimeoutExpired:
        print(subprocess.TimeoutExpired)

    #2. Run Cosign if not in cache
    try:
        result = subprocess.run(
        ["cosign", "verify", "--key", "/etc/cosign/cosign.pub", image_name],
        capture_output=True,
        text=True,
        timeout=10
        )
    except subprocess.TimeoutExpired:
        return False, f"Cosign verification timed out for {image_name}", False
    except FileNotFoundError:
        return False, "Cosign binary not found inside admission container", False


    #3. Save to cache if valid and return (True, "Verified by Cosign")
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