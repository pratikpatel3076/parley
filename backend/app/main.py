from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import auth, health, messages, users
from app.core.config import settings
from app.db.database import engine, init_db

STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SENSITIVE_PATH_PREFIXES = ("/api/v1/auth", "/api/v1/messages")


def _add_security_headers(path: str, response):
    """Never let auth or message responses be stored by a browser or proxy."""
    if path.startswith(SENSITIVE_PATH_PREFIXES):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@asynccontextmanager
async def lifespan(_: FastAPI):
    await init_db()
    yield
    await engine.dispose()


app = FastAPI(
    title=settings.APP_NAME,
    version="0.1.0",
    description=(
        "Parley backend. It stores opaque message ciphertext and public keys; "
        "message encryption and key management live on the client."
    ),
    lifespan=lifespan,
)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    _: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Return validation errors without echoing submitted values.

    The default FastAPI body includes the offending input. For this API that
    would echo authSecret, public keys, or a whole ciphertext in an error
    response, so only the location, message, and error type are returned.
    """
    errors = [
        {
            "loc": error.get("loc", []),
            "msg": error.get("msg", "Invalid value"),
            "type": error.get("type", "value_error"),
        }
        for error in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": errors})

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-Requested-With"],
)


@app.middleware("http")
async def enforce_origin_for_state_changes(request: Request, call_next):
    # Exact whole-origin equality against the allowlist. This deliberately does
    # not use prefix, suffix, substring, or wildcard matching, and a missing
    # Origin (or the literal "null") is never in the allowlist.
    if request.method in STATE_CHANGING_METHODS:
        origin = request.headers.get("origin")
        if origin not in settings.ALLOWED_ORIGINS:
            return _add_security_headers(
                request.url.path,
                JSONResponse(
                    status_code=403,
                    content={"detail": "Origin not allowed"},
                ),
            )
    response = await call_next(request)
    return _add_security_headers(request.url.path, response)


app.include_router(health.router)
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(messages.router)
