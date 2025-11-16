from ._mitre_base import *
from .relationship import RelationshipModel

# Labels: 
# kill_chain_phases.phase_name (tactical objectives)
class Technique(MitreBase):
    __optional_labels__ = [
        "enterpriseattack",
        "mobileattack",
        "icsattack",
    ]
    
    technique_of = Relationship('MitreBase', 'TECHNIQUEOF', model=RelationshipModel)
    created_by_ref = StringProperty()
    description = StringProperty()
    external_references = JSONProperty()
    kill_chain_phases = JSONProperty()
    object_marking_refs = JSONProperty()
    revoked = StringProperty()
    spec_version = StringProperty()
    type = StringProperty()
    x_mitre_contributors = JSONProperty()
    x_mitre_deprecated = StringProperty()
    x_mitre_detection = StringProperty()
    x_mitre_domains = JSONProperty()
    x_mitre_impact_type = JSONProperty()
    x_mitre_modified_by_ref = StringProperty()
    x_mitre_platforms = JSONProperty()
    x_mitre_remote_support = StringProperty()
    x_mitre_version = StringProperty()