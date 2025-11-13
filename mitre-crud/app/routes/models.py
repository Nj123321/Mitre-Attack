from fastapi import APIRouter, HTTPException, Query, Request
from app.services.repository_service import RepositoryService, ALLOWED_RESOURCES

from typing import Literal

router = APIRouter()
    
@router.get("/{resource}")
def get_model(request: Request, resource: Literal[tuple(ALLOWED_RESOURCES)], uuid: str = Query(..., description="UUID of the object")):
    response = {}
    
    if resource not in ALLOWED_RESOURCES:
        raise HTTPException(status_code=404, detail=f"Unknown resource '{resource}'")
    
    response["object"] = RepositoryService.get_model_uuid(resource, uuid)
    results, _ = RepositoryService.get_related_nodes(uuid, request.state.domain)

    for rel_type, related_node in results:
        response[rel_type] = response.get(rel_type, []) + [related_node._properties]
    return response