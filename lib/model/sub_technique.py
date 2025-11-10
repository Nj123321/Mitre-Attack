from .base_object import *
from ._mitre_base import MitreBase
from .technique import Technique

class SubTechnique(Technique):
    __optional_labels__ = [
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
    ]