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