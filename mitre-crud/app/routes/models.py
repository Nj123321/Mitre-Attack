from fastapi import APIRouter, HTTPException, Query, Request, Path
from app.services.repository_service import RepositoryService, ALLOWED_RESOURCES

from neomodel import DoesNotExist

from typing import Literal

router = APIRouter(prefix="/model")

@router.get(
    "/{resource_id}",
    description="retrieving all tactics",
)
def retrieve_matrix(
    request: Request,
    resource_id: str = Path(..., description="Tactic ID, e.g. TA0001")
):
    return {"tactic_id: " : tactic_id}

# for resource in ALLOWED_RESOURCES:

#     async def handler(
#         request: Request,
#         uuid: str = Query(..., description="UUID of the object"),
#         res=resource,
#     ):
#         response = {}

#         try:
#             response["object"] = RepositoryService.get_model_uuid(res, uuid)
#         except DoesNotExist:
#             raise HTTPException(status_code=404, detail=f"unable to find #{res} with uuid: #{uuid}")
#         results, _ = RepositoryService.get_related_nodes(uuid, request.state.domain)

#         for rel_type, related_node in results:
#             response.setdefault(rel_type, []).append(related_node._properties)

#         return response
    
#     handler.__name__ = f"get_{resource}_by_uuid"

#     router.add_api_route(
#         path=f"/{resource}",
#         endpoint=handler,
#         methods=["GET"],
#         responses={404: {"description": "unable to find #{res} with uuid: #{uuid}"}}
#     )