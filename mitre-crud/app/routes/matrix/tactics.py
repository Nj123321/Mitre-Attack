from fastapi import APIRouter, Request, Path, HTTPException
from app.services.repository_service import RepositoryService
from .technique import technique_router

tactic_router = APIRouter(prefix="/tactics")

@tactic_router.get(
    "/",
    description="retrieving all tactics",
)
def retrieve_matrix(request: Request):
    return {"tactic"}

@tactic_router.get(
    "/{tactic_id}",
    description="retrieving all tactics",
)
def retrieve_matrix(
    request: Request,
    tactic_id: str = Path(..., description="Tactic ID, e.g. TA0001")
):
    return {"tactic_id: " : tactic_id}

tactic_router.include_router(technique_router)