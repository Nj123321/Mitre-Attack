from neomodel import (db, DoesNotExist, StructuredNode, StringProperty, IntegerProperty,
    RelationshipTo, DateTimeProperty, JSONProperty, ArrayProperty, RelationshipManager)

class ResourceManager(StructuredNode):
    resource = StringProperty(required=True, unique_index=True)
    x_mitre_contents_serialized = JSONProperty(default=dict)