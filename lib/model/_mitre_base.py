from neomodel import (db, DoesNotExist, StructuredNode, StringProperty, IntegerProperty,
    RelationshipTo, DateTimeProperty, BooleanProperty, ArrayProperty, Relationship)
from .relationship import Relationship as RelationshipModel

class MitreBase(StructuredNode):
    __abstract_node__ = True
    
    x_mitre_attack_spec_version = StringProperty(required = True)
    stix_uuid = StringProperty(required=True, unique_index=True)
    name = StringProperty(required=True)
    attack_id = StringProperty()
    # modified = DateTimeProperty(required=True)
    # created = DateTimeProperty(required=True)
    # skipping object_marking_refs? - marking-definintoin model
    
    uses = RelationshipTo('MitreBase', 'USES', model=RelationshipModel)
    mitigates = RelationshipTo('MitreBase', 'MITIGATES', model=RelationshipModel)
    subtechnique_of = Relationship('MitreBase', 'SUBTECHNIQUE-OF', model=RelationshipModel)
    detects = RelationshipTo('MitreBase', 'DETECTS', model=RelationshipModel)
    attributed_to = RelationshipTo('MitreBase', 'ATTRIBUTED-TO', model=RelationshipModel)
    targets = RelationshipTo('MitreBase', 'TARGETS', model=RelationshipModel)
    revoked_by = RelationshipTo('MitreBase', 'REVOKED-BY', model=RelationshipModel)