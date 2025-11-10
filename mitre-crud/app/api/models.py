from fastapi import APIRouter, HTTPException, Query
from lib.model import *
from neomodel import db

router = APIRouter(prefix="/models")

ALLOWED_RESOURCES = {model.__name__: model for model in MODEL_LIST}
print(ALLOWED_RESOURCES)

related_nodes = """
MATCH (n {stix_uuid: $uuid})-[r]-(m)
RETURN type(r), m
"""

@router.get("/{resource}")
def get_model(resource: str, uuid: str = Query(..., description="UUID of the object")):
    """
    Example route: /models/technique?uuid=1234-5678
    """
    print("found endpoint")
    response = {}
    if resource not in ALLOWED_RESOURCES:
        raise HTTPException(status_code=404, detail=f"Unknown resource '{resource}'")

    print("finding object:")
    found_object = ALLOWED_RESOURCES[resource].nodes.get(stix_uuid=uuid)
    print("woogliewoo")
    response["object"]=found_object.__properties__
    
    results, _ = db.cypher_query(related_nodes, {'uuid': uuid})

    for rel_type, related_node in results:
        response[rel_type] = response.get(rel_type, []) + [related_node._properties]
    return response

@router.get("/{model_name}/details")
def get_model_details(model_name: str):
    return {"details_for": model_name}