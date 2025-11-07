from .base_object import *

# Labels: 
# kill_chain_phases.phase_name (tactical objectives)
class Technique(VersionedObject):
    LABELS = []
    name = StringProperty(required=True)
    # id = StringProperty(unique_index=True, required=True)
    # x_mitre_detection = StringProperty(required = True)
    # x_mitre_platforms = ArrayProperty(StringProperty(), required = True)