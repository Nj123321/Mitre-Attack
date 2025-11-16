from fastapi import FastAPI
from .routes import domain_base # imports routers

from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
from .routes import models

app = FastAPI()

# app.add_middleware(DomainExtractorMiddleware)

# Include routers (nesting)
app.include_router(domain_base.router)
app.include_router(models.router)