# hacky shared lib solution
import sys, os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)
# hacky solution --- end

from mitre_attack_pipeline import MitreAttackPipeline

attack = MitreAttackPipeline("https://github.com/mitre-attack/attack-stix-data.git")
for domain in ["enterprise-attack"]:
    for version in ["18.1"]:
        input("runing: " + version)
        attack.run(domain, version)