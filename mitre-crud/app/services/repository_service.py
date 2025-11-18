from mitre_common.model._mitre_base import MitreBase
from mitre_common.model import *
from neomodel import db, DoesNotExist

from neo4j.graph import Node

ALLOWED_RESOURCES = {model.__name__: model for model in MODEL_LIST}

class RepositoryService:
    related_nodes_query = """
MATCH (n {stix_uuid: $uuid})-[r]-(m)
RETURN type(r), m
"""

    get_matrix_query = """
MATCH (n:Matrix {attack_id: $attack_id})
OPTIONAL MATCH (n)-[:CONTAINS]->(t1:Tactic)
OPTIONAL MATCH (t1)<-[:TECHNIQUEOF]-(t2:Technique)
OPTIONAL MATCH (t2)<-[:SUBTECHNIQUEOF]-(t3:SubTechnique)

WITH n, t1, t2, collect(DISTINCT t3) AS subtechniques
WITH n,
     t1 AS tactic,
     collect(DISTINCT {
         technique: t2,
         subtechniques: subtechniques
     }) AS techniques
WITH n,
     collect(DISTINCT {
         tactic: tactic,
         techniques: techniques
     }) AS tactic_groups

RETURN 
    n AS matrix,
    tactic_groups
"""

    get_node_attack_id = """
    MATCH (n {attack_id: $attack_id})
    RETURN n
    """

    @classmethod
    def get_assosciations_related_to_node(clz, condition, relation_type, condition_two):
        print(condition)
        query = f"""
    MATCH (n{condition})-[{relation_type}]-(m{condition_two})
    RETURN collect(m)
    """
        results, _ = db.cypher_query(query)
        return results[0][0]

    @classmethod
    def construct_parameter_condition(clz, attribute, value):
        return f'{{{attribute}: "{value}"}}'
    
    @classmethod
    def get_models_domain(clz, resource, domain):
        if resource not in ALLOWED_RESOURCES:
            raise ValueError(f"resource \"{resource}\" not recognized")
        found_object = ALLOWED_RESOURCES[resource].nodes.filter(attack_id=domain)
        return found_object.__properties__

    @classmethod
    def get_model_uuid(clz, uuid):
        model = find_model_from_type(uuid.split("--")[0])
        # if resource not in ALLOWED_RESOURCES:
        #     raise ValueError(f"resource \"{resource}\" not recognized")
        # try:
        found_object = model.nodes.get(stix_uuid=uuid)
        # except DoesNotExist:
            # raise ValueError(f"{resource} with uuid {uuid} does not exist")
        if not isinstance(found_object, list):
            found_object = [found_object]
        return found_object
    
    @classmethod
    def get_model_attack_id(clz, attack_id):
        node, _ = db.cypher_query(clz.get_node_attack_id, {'attack_id': attack_id})
        found_nodes = []
        for obj in node[0]:
            found_nodes.append(find_model_from_type(obj._properties["type"]).inflate(obj))
        return found_nodes
    
    @classmethod
    def get_related_nodes(clz, uuid):
        return db.cypher_query(clz.related_nodes_query, {'uuid': uuid})
    
    @classmethod
    def get_matrix(clz, domain):
        matrix, _ = db.cypher_query(clz.get_matrix_query, {"attack_id": domain})
        if len(matrix) == 0:
            return None
        return matrix
    
    @classmethod
    def get_sub_techniques_per_technique(clz, attack_id):
        test = clz.get_assosciations_related_to_node(
            ":Technique " + clz.construct_parameter_condition("attack_id", attack_id), 
            ":SUBTECHNIQUEOF", 
            ":SubTechnique"
        )
        return test
    
    @classmethod
    def get_techniques_per_tactic(clz, attack_id):
        test = clz.get_assosciations_related_to_node(
            ":Tactic " + clz.construct_parameter_condition("attack_id", attack_id), 
            ":TECHNIQUEOF", 
            ":Technique"
        )
        return test
    
    @classmethod
    def get_tacitcs_in_matrix(clz, domain):
        test = clz.get_assosciations_related_to_node(
            clz.construct_parameter_condition("attack_id", domain), 
            ":CONTAINS", 
            ""
        )
        return test