from components.repository import Repository 
from unittest.mock import patch, MagicMock
from mitre_common.model import *
from mitre_common.commons import CustomPipelineKeys
import copy
import uuid as uuidLibrary
from datetime import datetime, timedelta

class TestRepository:
    def setup_method(self):
        self.patcher = patch.object(Repository, "__init__", lambda self: print("stubbed init"))
        self.patcher.start()
        self.repository = Repository()
    def teardown_method(self, method):
        self.patcher.stop()
    
    def repository_init_stub(monkeypatch):
        monkeypatch.setattr(Repository, "__init__", lambda self: print("hello"))
    
    def test_add_tactic_technique_relationships(self, tactic_json, attack_json):
        attack_uuid = str(uuidLibrary.uuid4())
        attack_2_uuid = str(uuidLibrary.uuid4())
        tactic_uuid = str(uuidLibrary.uuid4())
        tactic_2_uuid = str(uuidLibrary.uuid4())
        
        tactic_json_2 = copy.deepcopy(tactic_json) 
        attack_json_2 = copy.deepcopy(attack_json)
        
        attack_json["stix_uuid"] = "attack-pattern--" + attack_uuid
        attack_json_2["stix_uuid"] = "attack-pattern--" + attack_2_uuid
        tactic_json["stix_uuid"] = "x-mitre-tactic--" + tactic_uuid
        tactic_json_2["stix_uuid"] = "x-mitre-tactic--" + tactic_2_uuid 
        tactic_json["name"] = "Tactic1"
        tactic_json_2["name"] = "Tactic2"
        
        # create relationships
        attack_json_2["related_tactics"] = [
            "tactic1", "tactic2"
        ]
        attack_json["related_tactics"] = [
            "tactic1"
        ]
        constructed_object_list = {
            "x-mitre-tactic": {
                tactic_json["stix_uuid"]: tactic_json,
                tactic_json_2["stix_uuid"]: tactic_json_2,
            },
            "attack-pattern": {
                attack_json["stix_uuid"]: attack_json,
                attack_json_2["stix_uuid"]: attack_json_2,
            }
        }
        relationship_queue = {}
        self.repository._add_tactic_technique_relationships(constructed_object_list, relationship_queue)
        assert len(relationship_queue) == 3
        
        expected_relatiion_uuids = [
            self._construct_relation(attack_json_2["stix_uuid"], tactic_json["stix_uuid"]),
            self._construct_relation(attack_json_2["stix_uuid"], tactic_json_2["stix_uuid"]),
            self._construct_relation(attack_json["stix_uuid"], tactic_json["stix_uuid"]),
        ]
        for r_uuid in expected_relatiion_uuids:
            assert r_uuid in relationship_queue
            
    def test_add_tactic_matrix_relationships(self, matrix_json, tactic_json):
        tactic_uuid = str(uuidLibrary.uuid4())
        tactic_2_uuid = str(uuidLibrary.uuid4())
        matrix_uuid = str(uuidLibrary.uuid4())
        
        tactic_json_2 = copy.deepcopy(tactic_json)
        
        matrix_json["stix_uuid"] = "x-mitre-matrix--" + matrix_uuid
        tactic_json["stix_uuid"] = "x-mitre-tactic--" + tactic_uuid
        tactic_json_2["stix_uuid"] = "x-mitre-tactic--" + tactic_2_uuid 
        tactic_json["name"] = "Tactic1"
        tactic_json_2["name"] = "Tactic2"
        
        matrix_json["tactic_refs"] = [
            tactic_json["stix_uuid"],
            tactic_json_2["stix_uuid"],
        ]
        
        constructed_object_list = {
            "x-mitre-tactic": {
                tactic_json["stix_uuid"]: tactic_json,
                tactic_json_2["stix_uuid"]: tactic_json_2,
            },
            "x-mitre-matrix": {
                matrix_json["stix_uuid"]: matrix_json,
            }
        }
        relationship_queue = {}
        self.repository._add_tactic_matrix_relationships(constructed_object_list, relationship_queue)
        assert 2 == len(relationship_queue)
        expected_relation_uuids = [
            self._construct_relation(matrix_json["stix_uuid"], tactic_json["stix_uuid"]),
            self._construct_relation(matrix_json["stix_uuid"], tactic_json_2["stix_uuid"]),
        ]
        for rid in expected_relation_uuids:
            assert rid in relationship_queue
    
    def test_filter_resources(self, attack_json, monkeypatch):
        current_domain = "dummy_domain"
        removed_resource_uuid = str(uuidLibrary.uuid4())
        added_resource_uuid = str(uuidLibrary.uuid4())
        updated_resource_uuid = str(uuidLibrary.uuid4())
        unchanged_resource_uuid = str(uuidLibrary.uuid4())
        
        resource_added = copy.deepcopy(attack_json)
        resource_updated = copy.deepcopy(attack_json)
        resource_unchanged = copy.deepcopy(attack_json)
        
        current_time = datetime.now()
        
        resource_added.update({
            "stix_uuid": added_resource_uuid,
            CustomPipelineKeys.INT_MODIFIED: current_time.timestamp(),
        })
        resource_updated.update({
            "stix_uuid": updated_resource_uuid,
            CustomPipelineKeys.INT_MODIFIED: current_time.timestamp(),
        })
        resource_unchanged.update({
            "stix_uuid": unchanged_resource_uuid,
            CustomPipelineKeys.INT_MODIFIED: current_time.timestamp(),
        })
        
        dummy_resource_mapping = {
            "dummy_resource_type": {
                resource_added["stix_uuid"]: resource_added,
                resource_updated["stix_uuid"]: resource_updated,
                resource_unchanged["stix_uuid"]: resource_unchanged,
            },
            "relationship": {}
        }
        rm = ResourceManager.create({
            "resource": "dummy_resource_type", 
            "x_mitre_contents_serialized": {
                removed_resource_uuid: {
                    "modified": (current_time - timedelta(hours=10)).timestamp(),
                    "domains": [current_domain]
                },
                updated_resource_uuid: {
                    "modified": (current_time - timedelta(hours=2)).timestamp(),
                    "domains": [current_domain]
                },
                unchanged_resource_uuid: {
                    "modified": current_time.timestamp(),
                    "domains": [current_domain]
                }
            }
        })
        rm = rm[0]
        monkeypatch.setattr(Repository, "_get_resource_manager", lambda self, resource_type: rm)
        formatted_resources, relationships = self.repository.filter_resources(dummy_resource_mapping, current_domain)
        assert formatted_resources == {
            "dummy_resource_type": {
                "updated": [resource_updated],
                "added": [resource_added],
                "removed": [removed_resource_uuid],
            }
        }
            
    def _construct_relation(self, stix_uuid1, stix_uuid2):
        _, uuid1 = self.repository._type_from_stix_uuid(stix_uuid1)
        _, uuid2 = self.repository._type_from_stix_uuid(stix_uuid2)
        return "relationship--" + str(uuidLibrary.uuid5(uuidLibrary.NAMESPACE_DNS, uuid1 + uuid2))