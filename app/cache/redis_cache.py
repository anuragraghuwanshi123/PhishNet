import os
import json
import redis
from dotenv import load_dotenv

load_dotenv()

REDIS_URL = os.getenv("REDIS_URL")

redis_client = None

# Try connecting to Redis
if REDIS_URL:
    try:
        redis_client = redis.StrictRedis.from_url(
            REDIS_URL,
            decode_responses=True
        )

        redis_client.ping()
        print("✅ Redis connected")

    except Exception as e:
        print(f"⚠️ Redis unavailable: {e}")
        redis_client = None

else:
    print("⚠️ REDIS_URL not found. Running without Redis.")


def get_cached_prediction(key: str):
    """
    Get prediction from Redis cache
    """

    if redis_client is None:
        return None

    try:
        value = redis_client.get(key)

        if value:
            return json.loads(value)

    except Exception as e:
        print(f"Cache read failed: {e}")

    return None


def set_cached_prediction(
    key: str,
    value,
    expire_time: int = 3600
):
    """
    Store prediction in Redis cache
    """

    if redis_client is None:
        return

    try:
        redis_client.set(
            key,
            json.dumps(value),
            ex=expire_time
        )

    except Exception as e:
        print(f"Cache write failed: {e}")


def delete_cached_prediction(key: str):
    """
    Delete cache
    """

    if redis_client is None:
        return

    try:
        redis_client.delete(key)

    except Exception as e:
        print(f"Cache delete failed: {e}")