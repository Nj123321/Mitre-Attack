from ._mitre_base import *

class Analytic(MitreBase):
    __optional_labels__ = [
        "enterpriseattack",
        "mobileattack",
        "icsattack",
    ]
    created_by_ref = StringProperty()
    description = StringProperty()
    external_references = JSONProperty()
    object_marking_refs = JSONProperty()
    revoked = BooleanProperty()
    spec_version = StringProperty()
    type = StringProperty()
    x_mitre_attack_spec_version = StringProperty()
    x_mitre_deprecated = BooleanProperty()
    x_mitre_domains = JSONProperty()
    x_mitre_log_source_references = JSONProperty()
    x_mitre_modified_by_ref = StringProperty()
    x_mitre_mutable_elements = JSONProperty()
    x_mitre_platforms = JSONProperty()
    x_mitre_version = StringProperty()