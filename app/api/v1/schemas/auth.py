import uuid
from pydantic import BaseModel, Field
from datetime import datetime


class UserModel(BaseModel):
    uid: uuid.UUID
    username: str
    email: str
    first_name: str
    last_name: str
    is_verified: bool
    password_hash: str = Field(exclude=True)
    created_at: datetime
    updated_at: datetime


class UserCreateModel(BaseModel):
    first_name: str
    last_name: str
    username: str = Field(max_length=50)
    email: str = Field(max_length=50)
    password: str = Field(min_length=6)


class UserLoginModel(BaseModel):
    email: str = Field(max_length=50)
    password: str = Field(min_length=6)


class UserUpdateModel(BaseModel):
    username: str
    email: str | None = None
    password: str
