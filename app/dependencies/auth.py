from fastapi import HTTPException, status, Request, Depends
from fastapi.security import HTTPBearer
from fastapi.security.http import HTTPAuthorizationCredentials
from sqlmodel.ext.asyncio.session import AsyncSession
from typing import Any, List

from app.utils.tokens import decode_token
from app.db.redis import is_jti_in_blocklist
from app.db.main import get_session
from app.services.auth import UserService
from app.models.auth import User


user_service = UserService()


class TokenBearer(HTTPBearer):
    """Custom HTTP Bearer class for token authentication."""

    def __init__(self, auto_error: bool = True):
        super(TokenBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request) -> dict:
        credentials: HTTPAuthorizationCredentials = await super(
            TokenBearer, self
        ).__call__(request)

        token = credentials.credentials if credentials else None
        token_data = decode_token(token) if token else None

        if not self.is_token_valid(token):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid or expired access token",
            )

        if await is_jti_in_blocklist(token_data.get("jti")):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Token has been revoked",
            )

        self.verify_token_data(token_data)

        return token_data

    def is_token_valid(self, token: str) -> str:
        token_data = decode_token(token)
        return True if token_data is not None else False

    def verify_token_data(self, token_data):
        raise NotImplementedError("Subclasses must implement this method.")


class AccessTokenBearer(TokenBearer):
    """Bearer class for access token authentication."""

    def verify_token_data(self, token_data: dict) -> dict:
        if token_data and token_data.get("refresh"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access token required, refresh token provided",
            )
        return token_data

    def is_token_valid(self, token: str) -> str:
        token_data = decode_token(token)
        if token_data and not token_data.get("is_refresh_token", False):
            return True
        return False


class RefreshTokenBearer(TokenBearer):
    """Bearer class for refresh token authentication."""

    def verify_token_data(self, token_data: dict) -> dict:
        if token_data and not token_data.get("refresh"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Refresh token required, access token provided",
            )
        return token_data


async def get_current_user(
    token_details: dict = Depends(AccessTokenBearer()),
    session: AsyncSession = Depends(get_session),
):
    user_email = token_details["user"]["email"]
    user = await user_service.get_user_by_email(user_email, session)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return user


class RoleChecker:
    def __init__(self, allowed_roles: List[str]) -> None:
        self.allowed_roles = allowed_roles

    async def __call__(self, user: User = Depends(get_current_user)) -> Any:
        if user.role not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not permitted for your role",
            )
        return True
