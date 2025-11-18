from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.responses import JSONResponse
from sqlmodel.ext.asyncio.session import AsyncSession
from datetime import timedelta, datetime

from app.api.v1.schemas.auth import (
    UserCreateModel,
    UserUpdateModel,
    UserModel,
    UserLoginModel,
)
from app.db.main import get_session
from app.services.auth import UserService
from app.utils.tokens import create_access_token
from app.utils.pass_hash import verify_password
from app.dependencies.auth import (
    AccessTokenBearer,
    RefreshTokenBearer,
    get_current_user,
    RoleChecker,
)
from app.db.redis import add_jti_to_blocklist


router = APIRouter()
user_service = UserService()
access_token_bearer = AccessTokenBearer()
role_checker = RoleChecker(allowed_roles=["admin", "user"])

REFRESH_TOKEN_EXPIRY_DAYS = 7


@router.get(
    "/users", response_model=list[UserModel], dependencies=[Depends(role_checker)]
)
async def get_users(
    session: AsyncSession = Depends(get_session),
    user_details=Depends(access_token_bearer),
):
    users = await user_service.get_all_users(session)
    return users


@router.get(
    "/{user_uid}/", response_model=UserModel, dependencies=[Depends(role_checker)]
)
async def get_user(
    user_uid: str,
    session: AsyncSession = Depends(get_session),
    user_details=Depends(access_token_bearer),
):
    user = await user_service.get_user_by_uid(user_uid, session)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    return user


@router.put(
    "/{user_uid}/update-user/",
    status_code=status.HTTP_200_OK,
    response_model=UserModel,
    dependencies=[Depends(role_checker)],
)
async def update_user(
    user_uid: str,
    update_data: UserUpdateModel,
    session: AsyncSession = Depends(get_session),
    user_details=Depends(access_token_bearer),
):
    updated_user = await user_service.update_user(user_uid, update_data, session)
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    return updated_user


@router.delete(
    "/{user_uid}/delete-user/",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(role_checker)],
)
async def delete_user(
    user_uid: str,
    session: AsyncSession = Depends(get_session),
    user_details=Depends(access_token_bearer),
):
    return await user_service.delete_user(user_uid, session)


@router.post("/signup/", status_code=status.HTTP_201_CREATED, response_model=UserModel)
async def create_user_account(
    user_data: UserCreateModel, session: AsyncSession = Depends(get_session)
):
    email = user_data.email
    user_exists = await user_service.user_exists(email, session)
    if user_exists:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User with this email already exists",
        )
    new_user = await user_service.create_user(user_data, session)
    return new_user


@router.post("/login/")
async def login_user(
    login_data: UserLoginModel, session: AsyncSession = Depends(get_session)
):
    email = login_data.email
    password = login_data.password

    user = await user_service.get_user_by_email(email, session)
    if user is not None:
        is_password_valid = verify_password(password, user.password_hash)
        if is_password_valid:

            access_token = create_access_token(
                user_data={
                    "email": user.email,
                    "user_uid": str(user.uid),
                    "role": user.role,
                }
            )

            refresh_token = create_access_token(
                user_data={
                    "email": user.email,
                    "user_uid": str(user.uid),
                    "role": user.role,
                },
                refresh=True,
                expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRY_DAYS),
            )

            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={
                    "message": "Login successful✅",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_type": "bearer",
                    "user": {
                        "uid": str(user.uid),
                        "email": user.email,
                    },
                },
            )

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Invalid email or password",
    )


@router.get("/refresh-token")
async def get_new_access_token(
    token_details: dict = Depends(RefreshTokenBearer()),
):
    expiry_timestapte = token_details.get("exp")
    if datetime.fromtimestamp(expiry_timestapte) > datetime.now():
        new_access_token = create_access_token(user_data=token_details.get("user"))
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "access_token": new_access_token,
                "token_type": "bearer",
            },
        )

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Refresh token expired",
    )


@router.get("/logout", status_code=status.HTTP_200_OK)
async def revoke_token(
    token_details: dict = Depends(AccessTokenBearer()),
):
    jti = token_details.get("jti")
    await add_jti_to_blocklist(jti)
    return JSONResponse(
        content={"message": "Token successfully revoked✅"},
        status_code=status.HTTP_200_OK,
    )


@router.get("/me", response_model=UserModel)
async def get_current_user(
    user=Depends(get_current_user), _: bool = Depends(role_checker)
):
    return user
