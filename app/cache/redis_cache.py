import os
import json
import redis
from dotenv import load_dotenv

load_dotenv()

REDIS_URL = os.getenv(
    "REDIS_URL",
    "redis://localhost:6379"
)

redis_client = redis.StrictRedis.from_url(
    REDIS_URL,
    decode_responses=True
)


def get_cached_prediction(key: str):
    """
    Get prediction from Redis cache
    """

    value = redis_client.get(key)

    if value:
        return json.loads(value)

    return None


def set_cached_prediction(
    key: str,
    value: dict,
    expire_time: int = 3600
):
    """
    Store prediction in Redis cache

    expire_time:
        default = 1 hour
    """

    redis_client.set(
        key,
        json.dumps(value),
        ex=expire_time
    )


def delete_cached_prediction(key: str):
    """
    Delete cache
    """

    redis_client.delete(key)