"""FastAPI application entrypoint."""

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

from .controllers import router as message_router

app = FastAPI(title="SecureMessageService", version="1.0.0", docs_url="/docs", redoc_url="/redoc", openapi_url="/openapi.json")

# Include API router
app.include_router(message_router, prefix="/api/v1")


@app.get('/health', tags=["Health"], include_in_schema=True)
async def health():
    return {"status": "ok"}


def custom_openapi():
    """Generate OpenAPI schema with Bearer JWT security scheme applied to endpoints."""
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(title=app.title, version=app.version, routes=app.routes)
    components = openapi_schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["BearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
    }

    # Apply security requirement to all paths except health and docs/openapi
    for path, path_item in openapi_schema.get("paths", {}).items():
        if path in ["/health", app.openapi_url, app.docs_url, app.redoc_url]:
            continue
        for operation in path_item.values():
            operation.setdefault("security", [{"BearerAuth": []}])

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi
