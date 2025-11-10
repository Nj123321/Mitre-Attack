from neomodel import (db, DoesNotExist, StructuredNode, StringProperty, IntegerProperty,
    RelationshipTo, DateTimeProperty, JSONProperty, ArrayProperty, RelationshipManager)

class Collection(StructuredNode):
    __optional_labels__ = [
        "enterpriseattack",
        "mobileattack",
        "icsattack",
    ]
    
    stix_uuid = StringProperty(required=True, unique_index=True)
    x_mitre_contents_serialized = JSONProperty(default={})