from lib.model import *
from neomodel import db

from neo4j.graph import Node

ALLOWED_RESOURCES = {model.__name__: model for model in MODEL_LIST}

class RepositoryService:
    related_nodes_query = """
MATCH (n {stix_uuid: $uuid})-[r]-(m)
WHERE $label IS NULL OR $label IN labels(m)
RETURN type(r), m
"""

    get_matrices_query = """
MATCH (n:Matrix)
WHERE $dynamic_label IN labels(n)
OPTIONAL MATCH (n)-[r]-(m)
RETURN n, collect(m) AS related_nodes
"""

    get_techniques = """
MATCH (m)-[r:TECHNIQUEOF]-(n {stix_uuid: $uuid})
WHERE $label IN labels(m)
RETURN m
"""

    @classmethod
    def get_model_uuid(clz, resource, uuid):
        found_object = ALLOWED_RESOURCES[resource].nodes.get(stix_uuid=uuid)
        print(found_object.labels)
        return found_object.__properties__
    
    @classmethod
    def get_related_nodes(clz, uuid, label=None):
        params = {'uuid': uuid}
        params["label"] = label if label else None
        return db.cypher_query(clz.related_nodes_query, params)
    
    @classmethod
    def get_matrix(clz, domain):
        matrix, _ = db.cypher_query(clz.get_matrices_query, {"dynamic_label": domain})
        if len(matrix) == 0:
            return None
        matrix[0]
        return matrix
    
    @classmethod
    def get_techniques_per_tactic(clz, uuid, domain):
        techniques, _ = db.cypher_query(clz.get_techniques, {'uuid': uuid, 'label': domain})
        # flatten due to driver
        techniques = [batch[0] for batch in techniques]
        [print(type(batch)) for batch in techniques]
        return techniques
    
    @classmethod
    def flatten_nodes(query_elem):
        if isinstance(query_elem, Node):
            return dict(query_elem)
        