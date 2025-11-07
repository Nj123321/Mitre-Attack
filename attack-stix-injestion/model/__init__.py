from .sub_technique import SubTechnique
from .technique import Technique
from .campaign import Campaign
from .mitigation import Mitigation
from .group import Group
from .relationship import Relationship
from .analytic import Analytic
from .collection import Collection
from .data_component import DataComponent
from .data_source import DataSource
from .detection_strategy import DetectionStrategy
from .matrix import Matrix
from .tactic import Tactic
from .malware import Malware
from .tool import Tool

# __all__ = [
#     "Analytic",
#     "BaseObject",
#     "SubTechnique",
#     "Tactic",
#     "Technique",
# ]

from neomodel import install_all_labels
def init_models():
    install_all_labels()