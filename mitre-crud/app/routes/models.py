from fastapi import APIRouter, HTTPException, Query, Request, Depends
from typing import Optional
from app.services.repository_service import RepositoryService, ALLOWED_RESOURCES

from typing import Literal

router = APIRouter(prefix="/model")


def either_attack_id_or_uuid(
    uuid: Optional[str] = Query(None),
    attack_id: Optional[str] = Query(None),
):
    if not uuid and not attack_id:
        raise HTTPException(
            status_code=400,
            detail="Either 'uuid' or 'attack_id' must be provided."
        )
    if uuid and attack_id:
        raise HTTPException(
            status_code=400,
            detail="Provide only one of 'uuid' or 'attack_id', not both."
        )
    if uuid:
        return {"uuid": uuid}
    return {"attack_id": attack_id}

@router.get(
    "/",
    description="retrieving specifics for a model",
)
def retrieve_matrix(
    request: Request,
    resource_id = Depends(either_attack_id_or_uuid)
):
    found_objects = []
    if "attack_id" in resource_id:
        found_objects = RepositoryService.get_model_attack_id(resource_id["attack_id"])
    else:
        found_objects = RepositoryService.get_model_uuid(resource_id["uuid"])
    response = []
    for object in found_objects:
        object = object.__properties__
        formatted_resource = {}
        if object.get("revoked", False):
            continue
        formatted_resource["object"] = object
        results, _ = RepositoryService.get_related_nodes(object["stix_uuid"])
        for rel_type, related_node in results:
            formatted_resource.setdefault(rel_type, []).append({
                "uuid": related_node["stix_uuid"],
                "name": related_node["name"],
                "attack_id": related_node["attack_id"],
            })
        response.append(formatted_resource)
    # raise HTTPException(status_code=404, detail=f"unable to find #{res} with uuid: #{uuid}")

    return response