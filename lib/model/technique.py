from .base_object import *
from ._mitre_base import MitreBase
from neomodel import Relationship

# Labels: 
# kill_chain_phases.phase_name (tactical objectives)
class Technique(VersionedObject, MitreBase):
    __optional_labels__ = [
        # platforms: x_mitre_platforms
        "NetworkDevices",
        "SaaS",
        "OfficeSuite",
        "IdentityProvider",
        "Windows",
        "Containers",
        "Office365",
        "PRE",
        "macOS",
        "IaaS",
        "Linux",
        "ESXi",
        
        "enterpriseattack",
        "mobileattack",
        "icsattack",
    ]
    technique_of = Relationship('MitreBase', 'TECHNIQUE-OF')