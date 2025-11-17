from ._mitre_base import MitreBase

class Tool(MitreBase):
    __optional_labels__ = [
        "enterpriseattack",
        "mobileattack",
        "icsattack",
    ]