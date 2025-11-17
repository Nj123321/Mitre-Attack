from ._mitre_base import *

class DetectionStrategy(MitreBase):
    __optional_labels__ = [
        "enterpriseattack",
        "mobileattack",
        "icsattack",
    ]