from fastapi import APIRouter

from app.core.config import settings

router = APIRouter(tags=["health"])


@router.get("/health")
@router.get("/api/health", include_in_schema=False)
async def health() -> dict[str, str]:
    return {"status": "ok", "app": settings.APP_NAME}
