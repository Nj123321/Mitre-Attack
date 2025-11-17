from neomodel import (db, DoesNotExist, StructuredNode, StringProperty, IntegerProperty,
    RelationshipTo, DateTimeProperty, JSONProperty, ArrayProperty, RelationshipManager)

class ResourceManager(StructuredNode):
    resource = StringProperty(required=True, unique_index=True)
    
    """
    map containing: {
        "resource-uuid": {
            "modified": float(timestamp)
            "domains": arr(string)
        }
        ....
    }
    
    used to track resource modification across domains (resources can be shared across domains),
    domains field is neccesarry to determine which domains have removed / omitted resources
    in their updated stix files
    
    also comment in Repository.perform_batch_operation that explains domain field
    """
    x_mitre_contents_serialized = JSONProperty(default=dict)