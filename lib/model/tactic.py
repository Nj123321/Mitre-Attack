from ._mitre_base import *

class Tactic(MitreBase):
    __optional_labels__ = [
        "enterpriseattack",
        "mobileattack",
        "icsattack",
    ]
    
    name = StringProperty(required=True, unique_index=True)