from mitre_attack_pipeline import MitreAttackPipeline

attack = MitreAttackPipeline("https://github.com/mitre-attack/attack-stix-data.git")
attack.run()