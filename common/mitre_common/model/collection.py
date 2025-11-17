from neomodel import (db, DoesNotExist, StructuredNode, StringProperty, IntegerProperty,
    RelationshipTo, DateTimeProperty, JSONProperty, ArrayProperty, RelationshipManager)

class Collection(StructuredNode):
    __optional_labels__ = [
        "enterpriseattack",
        "mobileattack",
        "icsattack",
    ]
    
    stix_uuid = StringProperty(required=True, unique_index=True)
    created = StringProperty()
    created_by_ref = StringProperty()
    description = StringProperty()
    modified = StringProperty()
    name = StringProperty()
    object_marking_refs = JSONProperty()
    spec_version = StringProperty()
    type = StringProperty()
    x_mitre_attack_spec_version = StringProperty()