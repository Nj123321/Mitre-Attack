from ._mitre_base import *

class Tactic(MitreBase):
    __optional_labels__ = [
        "enterpriseattack",
        "mobileattack",
        "icsattack",
    ]
    
    # override properties
    attack_id = StringProperty(required=True, unique_index=True)
    
    name = StringProperty(required=True)
    created_by_ref = StringProperty()
    description = StringProperty()
    external_references = JSONProperty()
    object_marking_refs = JSONProperty()
    revoked = StringProperty()
    spec_version = StringProperty()
    x_mitre_deprecated = StringProperty()
    x_mitre_domains = JSONProperty()
    x_mitre_modified_by_ref = StringProperty()
    x_mitre_shortname = StringProperty()
    x_mitre_version = StringProperty()