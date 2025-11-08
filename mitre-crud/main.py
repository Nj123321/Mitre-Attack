from fastapi import FastAPI
from .api import models, matrix  # imports routers

app = FastAPI()

# Include routers (nesting)
app.include_router(models.router)
app.include_router(matrix.router)