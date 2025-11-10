from neomodel import (db, DoesNotExist, StructuredNode, StringProperty, IntegerProperty,
    RelationshipTo, DateTimeProperty, BooleanProperty, ArrayProperty, RelationshipManager)
from.relationship import Relationship

class MitreBase(StructuredNode):
    __abstract_node__ = True
    
    x_mitre_attack_spec_version = StringProperty(required = True)
    attack_uuid = StringProperty(required=True, unique_index=True)
    name = StringProperty(required=True)
    attack_id = StringProperty()
    # modified = DateTimeProperty(required=True)
    # created = DateTimeProperty(required=True)
    # skipping object_marking_refs? - marking-definintoin model
    
    uses = RelationshipTo('MitreBase', 'USES', model=Relationship)
    mitigates = RelationshipTo('MitreBase', 'MITIGATES', model=Relationship)
    subtechnique_of = RelationshipTo('MitreBase', 'SUBTECHNIQUE-OF', model=Relationship)
    detects = RelationshipTo('MitreBase', 'DETECTS', model=Relationship)
    attributed_to = RelationshipTo('MitreBase', 'ATTRIBUTED-TO', model=Relationship)
    targets = RelationshipTo('MitreBase', 'TARGETS', model=Relationship)
    revoked_by = RelationshipTo('MitreBase', 'REVOKED-BY', model=Relationship)