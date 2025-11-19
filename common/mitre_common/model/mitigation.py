from ._mitre_base import *

class Mitigation(MitreBase):
    __optional_labels__ = [
        "enterpriseattack",
        "mobileattack",
        "icsattack",
    ]
    
    created_by_ref = StringProperty()
    external_references = JSONProperty()
    description = StringProperty()
    object_marking_refs = JSONProperty()
    revoked = BooleanProperty()
    spec_version = StringProperty()
    x_mitre_deprecated = BooleanProperty()
    x_mitre_domains = JSONProperty()
    x_mitre_modified_by_ref = StringProperty()
    x_mitre_version = StringProperty()