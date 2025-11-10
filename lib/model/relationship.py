from neomodel import StructuredNode, StringProperty, RelationshipTo, StructuredRel, IntegerProperty

class Relationship(StructuredRel):    
    # weird - relationship--00814703-3c3b-4872-89e9-cea4ba5edf2d is faulty
    description = StringProperty(required = False)
    modified = StringProperty(required = True)
    spec_version = StringProperty(required = True)
    created = StringProperty(required = True)