from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import models
from .config import get_settings
from .db import Base, SessionLocal, engine
from .middleware import authenticate_and_audit
from .routers import analyses, assets, auth, checks, contracts, dashboard, notifications, organization, products, reports, sboms, software, vulnerabilities, vulnerability_work
from .routers import analysis_controls, analysis_history, lifecycle_catalog
from .services.auth import ensure_admin


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.auto_create_schema:
        Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        ensure_admin(db)
    yield


settings = get_settings()
app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="SBOM·취약점 분석 도구의 결과를 인프라 자산에 연결하고 CVE 조치를 추적하는 운영 API",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.middleware("http")(authenticate_and_audit)

app.include_router(auth.router, prefix="/api")
app.include_router(assets.router, prefix="/api")
app.include_router(software.router, prefix="/api")
app.include_router(organization.router, prefix="/api")
app.include_router(products.router, prefix="/api")
app.include_router(checks.router, prefix="/api")
app.include_router(contracts.router, prefix="/api")
app.include_router(sboms.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(vulnerabilities.router, prefix="/api")
app.include_router(vulnerability_work.router, prefix="/api")
app.include_router(analysis_controls.router, prefix="/api")
app.include_router(analysis_history.router, prefix="/api")
app.include_router(lifecycle_catalog.router, prefix="/api")
app.include_router(analyses.router, prefix="/api")
app.include_router(notifications.router, prefix="/api")
app.include_router(reports.router, prefix="/api")


@app.get("/health", tags=["system"])
def health():
    return {"status": "ok"}
