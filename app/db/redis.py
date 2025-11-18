import redis.asyncio as aioredis
from app.core.config import Config


JTI_EXPIRY = 3600


token_blocklist = aioredis.StrictRedis(
    host=Config.REDIS_HOST,
    port=Config.REDIS_PORT,
    db=0,
)


async def add_jti_to_blocklist(jti: str):
    """Add a JTI to the Redis blocklist with an expiry time."""
    await token_blocklist.set(name=jti, value="", ex=JTI_EXPIRY)


async def is_jti_in_blocklist(jti: str) -> bool:
    """Check if a JTI is in the Redis blocklist."""
    exists = await token_blocklist.exists(jti)
    return bool(exists)
