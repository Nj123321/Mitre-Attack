from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
from .routes import models
from .routes import matrix

app = FastAPI()

app.include_router(matrix.router)
app.include_router(models.router)