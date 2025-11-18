from fastapi import HTTPException, status
from sqlmodel.ext.asyncio.session import AsyncSession
from app.models.auth import User
from app.api.v1.schemas.auth import UserUpdateModel, UserCreateModel
from sqlmodel import select, desc
from app.utils.pass_hash import generate_password_hash


class UserService:
    async def get_all_users(self, session: AsyncSession):
        statement = select(User).order_by(desc(User.created_at))
        result = await session.exec(statement)
        return result.all()

    async def get_user_by_email(self, email: str, session: AsyncSession):
        statement = select(User).where(User.email == email)
        result = await session.exec(statement)
        user = result.first()
        return user if user else None

    async def get_user_by_uid(self, uid: str, session: AsyncSession):
        statement = select(User).where(User.uid == uid)
        result = await session.exec(statement)
        user = result.first()
        return user if user else None

    async def user_exists(self, email: str, session: AsyncSession):
        user = await self.get_user_by_email(email, session)
        return True if user is not None else False

    async def create_user(self, user_data: UserCreateModel, session: AsyncSession):
        user_data_dict = user_data.model_dump(exclude={"password"})
        new_user = User(**user_data_dict)
        print(
            f"Creating user with password: {user_data.password} ({type(user_data.password)})"
        )
        new_user.password_hash = generate_password_hash(user_data.password)
        new_user.role = "user"
        session.add(new_user)
        await session.commit()
        return new_user

    async def update_user(
        self, user_uid: str, update_data: UserUpdateModel, session: AsyncSession
    ):
        user_to_update = await self.get_user_by_uid(user_uid, session)
        if user_to_update is not None:
            update_data_dict = update_data.model_dump()

            for key, value in update_data_dict.items():
                setattr(user_to_update, key, value)

            session.add(user_to_update)
            await session.commit()
            return user_to_update

        return None

    async def delete_user(self, user_uid: str, session: AsyncSession):
        user_to_delete = await self.get_user_by_uid(user_uid, session)
        if user_to_delete is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )
        await session.delete(user_to_delete)
        await session.commit()
        return {"detail": "User deleted successfully"}
