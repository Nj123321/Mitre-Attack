import os
from .mitre_attack_pipeline import MitreAttackPipeline

attack = MitreAttackPipeline(os.getenv("DOWNLOAD_MITRE_DATA", False))

domain_list = os.getenv("DOMAIN").split(",")
ver_list = os.getenv("DOMAINVER").split(",")

for domain in domain_list:
    for version in ver_list:
        attack.run(domain, version)