# # hacky shared lib solution
import sys, os

# PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# if PROJECT_ROOT not in sys.path:
#     sys.path.append(PROJEC_ROOT)
# # hacky solution --- endT

from .mitre_attack_pipeline import MitreAttackPipeline

attack = MitreAttackPipeline("https://github.com/mitre-attack/attack-stix-data.git")

d = os.getenv("DOMAIN", "enterprise-attack")
dver = os.getenv("DOMAINVER", "17.1")
for domain in ["enterprise-attack", "mobile-attack"]:
    for version in ["17.0", "17.1", "18.0", "18.1"]:
        # input("runing: " + version)it
        attack.run(domain, version)