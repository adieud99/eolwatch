from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import models
from .config import get_settings
from .db import Base, engine
from .routers import assets, checks, contracts, dashboard, organization, products, sboms, software


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.auto_create_schema:
        Base.metadata.create_all(bind=engine)
    yield


settings = get_settings()
app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="하드웨어 수명주기와 CycloneDX SBOM을 연결하는 통합 EOL 관리 API",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(assets.router, prefix="/api")
app.include_router(software.router, prefix="/api")
app.include_router(organization.router, prefix="/api")
app.include_router(products.router, prefix="/api")
app.include_router(checks.router, prefix="/api")
app.include_router(contracts.router, prefix="/api")
app.include_router(sboms.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")


@app.get("/health", tags=["system"])
def health():
    return {"status": "ok"}
