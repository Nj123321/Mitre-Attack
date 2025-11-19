from neomodel import StructuredNode, StringProperty, RelationshipTo, StructuredRel, IntegerProperty

class RelationshipModel(StructuredRel):    
    # weird - relationship--00814703-3c3b-4872-89e9-cea4ba5edf2d is faulty
    description = StringProperty(required = False)
    modified = StringProperty(required = True)
    spec_version = StringProperty()
    created = StringProperty()
    stix_uuid = StringProperty(required=True, unique_index=True)