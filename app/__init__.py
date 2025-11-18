from fastapi import FastAPI
from app.api.v1.routes import auth
from contextlib import asynccontextmanager
from app.db.main import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Starting up the FastAPI application...")
    await init_db()
    yield
    print("Shutting down the FastAPI application...")


version = "v1"

app = FastAPI(
    title="FastAPI",
    description="A simple FastAPI application",
    version=version,
)
app.include_router(auth.router, prefix=f"/api/{version}/auth")
