from mitre_common.model import *
from neomodel import db

from neo4j.graph import Node

ALLOWED_RESOURCES = {model.__name__: model for model in MODEL_LIST}

class RepositoryService:
    related_nodes_query = """
MATCH (n {stix_uuid: $uuid})-[r]-(m)
WHERE $label IS NULL OR $label IN labels(m)
RETURN type(r), m
"""

    get_matrix_query = """
MATCH (n:Matrix)
WHERE $dynamic_label IN labels(n)
OPTIONAL MATCH (n)-[:CONTAINS]->(t1)
OPTIONAL MATCH (t1)<-[:TECHNIQUEOF]-(t2)

WITH n, t1 as tactics, collect(t2) AS techniques
WITH n,
     collect({
         tactic: tactics,
         techniques: techniques
     }) AS tactic_groups

RETURN n AS matrix, tactic_groups
"""
    get_tactics_related_to_matrix = """
    MATCH (m:Matrix)-[:CONTAINS]->(t:Tactic)
WHERE $dynamic_label IN labels(m)
RETURN t;
"""

    get_techniques = """
MATCH (m)-[r:TECHNIQUEOF]-(n {attack_id: $attack_id})
WHERE $label IN labels(m)
RETURN m
"""

    @classmethod
    def get_models_domain(clz, resource, domain):
        if resource not in ALLOWED_RESOURCES:
            raise ValueError(f"resource \"{resource}\" not recognized")
        found_object = ALLOWED_RESOURCES[resource].nodes.filter(attack_id=domain)
        return found_object.__properties__

    @classmethod
    def get_model_uuid(clz, resource, uuid):
        if resource not in ALLOWED_RESOURCES:
            raise ValueError(f"resource \"{resource}\" not recognized")
        found_object = ALLOWED_RESOURCES[resource].nodes.get(stix_uuid=uuid)
        return found_object.__properties__
    
    @classmethod
    def get_model_attack_id(clz, resource, attack_id):
        if resource not in ALLOWED_RESOURCES:
            raise ValueError(f"resource \"{resource}\" not recognized")
        found_object = ALLOWED_RESOURCES[resource].nodes.get(attack_id=attack_id)
        return found_object.__properties__
    
    @classmethod
    def get_related_nodes(clz, uuid, label=None):
        params = {'uuid': uuid}
        params["label"] = label if label else None
        return db.cypher_query(clz.related_nodes_query, params)
    
    @classmethod
    def get_matrix(clz, domain):
        matrix, _ = db.cypher_query(clz.get_matrix_query, {"dynamic_label": domain})
        if len(matrix) == 0:
            return None
        return matrix
    
    @classmethod
    def get_techniques_per_tactic(clz, attack_id, domain):
        techniques, _ = db.cypher_query(clz.get_techniques, {'attack_id': attack_id, 'label': domain})
        techniques = [batch[0] for batch in techniques]
        return techniques
    
    @classmethod
    def get_tacitcs_in_matrix(clz, domain):
        tactics, _ = db.cypher_query(clz.get_tactics_related_to_matrix, {"dynamic_label": domain})
        return [batch[0] for batch in tactics]