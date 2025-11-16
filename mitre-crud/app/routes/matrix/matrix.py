from fastapi import APIRouter, Request, Query, HTTPException
from app.services.repository_service import RepositoryService
from .tactics import tactic_router

router = APIRouter(prefix="/matrix")

@router.get(
    "/",
    description="retireving attack matrix and related tactics, techniques at another endpoint",
)
def retrieve_matrix(request: Request):
    matrices_formatted = []
    query_result =  RepositoryService.get_matrix(request.state.domain)
    if not query_result:
        raise HTTPException(status_code=404, detail=f"no matrix found")
    for matrix_query_result in query_result:
        matrices_formatted.append({
            "matrix": dict(matrix_query_result[0]),
            'tactics': [ dict(tactic) for tactic in matrix_query_result[1]]
        })
    return matrices_formatted

router.include_router(tactic_router)

# @router.get("/tactics")
# def retrieve_techniques_tactics(request: Request, uuid: str = Query(..., description="UUID of the object")):
#     return RepositoryService.get_techniques_per_tactic(uuid, request.state.domain)
