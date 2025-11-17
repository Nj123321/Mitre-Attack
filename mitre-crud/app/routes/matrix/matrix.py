from fastapi import APIRouter, Request, Query, HTTPException
from app.services.repository_service import RepositoryService
from .tactics import tactic_router

router = APIRouter(prefix="/matrix")

@router.get(
    "/",
    description="retireving attack matrix and related tactics, techniques at another endpoint",
)
def retrieve_matrix(request: Request):
    # query_result =  RepositoryService.get_matrix(request.state.domain)
    return {"notimplemented": request.state.domain}

@router.get(
    "/full",
    description="retireving attack matrix and related tactics, techniques at another endpoint",
)
def retrieve_matrix(request: Request):
    return RepositoryService.get_matrix(request.state.domain)

router.include_router(tactic_router)
