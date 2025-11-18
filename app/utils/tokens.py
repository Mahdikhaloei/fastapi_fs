from datetime import datetime, timedelta
import logging
from app.core.config import Config
import jwt
import uuid


ACCESS_TOKEN_EXPIRY = 3600  # 1 hour in seconds


def create_access_token(
    user_data: dict, expires_delta: timedelta | None = None, refresh: bool = False
) -> str:

    payload = {}

    payload["user"] = user_data
    payload["exp"] = datetime.now() + (
        expires_delta if expires_delta else timedelta(seconds=ACCESS_TOKEN_EXPIRY)
    )
    payload["jti"] = str(uuid.uuid4())
    payload["refresh"] = refresh

    token = jwt.encode(
        payload=payload,
        key=Config.JWT_SECRET_KEY,
        algorithm=Config.JWT_ALGORITHM,
    )

    return token


def decode_token(token: str) -> dict:
    try:
        decoded_payload = jwt.decode(
            jwt=token,
            key=Config.JWT_SECRET_KEY,
            algorithms=[Config.JWT_ALGORITHM],
        )
        return decoded_payload
    except jwt.PyJWTError as e:
        logging.error(e)
        return None
    except jwt.ExpiredSignatureError:
        raise Exception("Token has expired")
    except jwt.InvalidTokenError:
        raise Exception("Invalid token")
