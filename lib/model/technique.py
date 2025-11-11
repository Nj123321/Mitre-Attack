from ._mitre_base import *

# Labels: 
# kill_chain_phases.phase_name (tactical objectives)
class Technique(MitreBase):
    __optional_labels__ = [
        "enterpriseattack",
        "mobileattack",
        "icsattack",
    ]
    
    technique_of = Relationship('MitreBase', 'TECHNIQUE-OF')