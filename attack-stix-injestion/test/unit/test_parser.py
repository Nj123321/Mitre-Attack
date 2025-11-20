from components.parser import Parser 
from unittest.mock import patch

from mitre_common.commons import CustomPipelineKeys

class TestParser:
    
    def setup_method(self):
        self.parser = Parser()
    
    def test_derive_attributes(self, attack_json, monkeypatch):
        attack_json["test_basic_ex"] = 3
        attack_json["test_array"] = [0, 4, 2]
        attack_json["test_dict"] = {
            "first": "uno",
            "second": "dos",
        }
        attack_json["test_array_dict"] = [
            {
                "arb_key": "incorrect"
            },
            3,
            {
                "arb_key": "correct"
            }
        ]
        
        monkeypatch.setattr(Parser, "load_mapping_cache", lambda self, type: {
            "derived_attributes": {
                "extracted_basic_ex": "test_basic_ex",
                "extracted_array": "test_array.[1]",
                "extracted_dict": "test_dict.second",
                "extracted_array_dict": "test_array_dict.[2].arb_key",
            }
        })
        self.parser._derive_attributes(attack_json)
        
        assert "test_basic_ex" in attack_json
        assert "test_array" in attack_json
        assert "test_dict" in attack_json
        assert "test_array_dict" in attack_json
        
        assert attack_json["extracted_basic_ex"] == 3
        assert attack_json["extracted_array"] == 4
        assert attack_json["extracted_dict"] == "dos"
        assert attack_json["extracted_array_dict"] == "correct"
    
    def test_add_required_meta_data_fields(self, attack_json):
        # test technique
        attack_json["modified"] = "2025-11-01T08:28:28.000000Z"
        if "x_mitre_is_subtechnique" in attack_json:
            attack_json.pop("x_mitre_is_subtechnique")
        self.parser._add_required_meta_data_fields(attack_json)
        assert attack_json[CustomPipelineKeys.EXTRACTED_TYPE] == "attack-pattern"
        assert attack_json[CustomPipelineKeys.INT_MODIFIED] == 1761985708.0
        
        # test sub technique
        attack_json["x_mitre_is_subtechnique"] = True
        self.parser._add_required_meta_data_fields(attack_json)
        assert attack_json[CustomPipelineKeys.EXTRACTED_TYPE] == "sub-attack-pattern"
        assert attack_json[CustomPipelineKeys.INT_MODIFIED] == 1761985708.0
        
    def test_transform_fields(self, attack_json, monkeypatch):
        attack_json["old_attribute"] = 10
        monkeypatch.setattr(Parser, "load_mapping_cache", lambda self, type: {
            "attributes": {
                "new_attribute": "old_attribute",
            }
        })
        self.parser._transform_fields(attack_json)
        assert "old_attribute" not in attack_json
        assert attack_json["new_attribute"] == 10
        
    def test_add_labels(self, attack_json, monkeypatch):
        attack_json["basic_label"] = "basic_label_value"
        attack_json["array_label"] = [
            {
                "label": "badlabel1"
            },
            {
                "label": "basic_label_value_2"
            },
            {
                "label": "badlabel2"
            }
        ]
        monkeypatch.setattr(Parser, "load_mapping_cache", lambda self, type: {
            "derived_labels": [
                "basic_label",
                "array_label.[1].label"
            ]
        })
        self.parser._add_labels(attack_json)
        assert "basic_label_value" in attack_json[CustomPipelineKeys.CUSTOM_NODE_LABELS]
        assert "basic_label_value_2" in attack_json[CustomPipelineKeys.CUSTOM_NODE_LABELS]
        
    def test_filter_query_path(self):
        path, required = self.parser._filter_query_path("testpath!")
        assert path == "testpath"
        assert required == True
        
        path, required = self.parser._filter_query_path("testpathNotRequired")
        assert path == "testpathNotRequired"
        assert required == False