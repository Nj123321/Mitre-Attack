# handles json logic / field extraction / labels
# takes in hashes as inputs

# stores filters? as jsons? if time? parse based on jsons / transfomrs jsons 
# dyanmcailly creates filters based on class name -> file mapping
import json
import os
from typing import Any, Union
import re
import lib.constants
from datetime import datetime, timezone

# creates id -> object mapping, for faster lookup in repository layer
# also handles trasnfomations / labels / validation
class Parser:
    REMOVED_VALUES = ["object_marking_refs"]
    MAPPING_BASE = "resources/mappings/"
    
    def __init__(self):
        self.mapping_cache = {}
        print("initilaizing parser")
    def parse_data(self, json_objects):
        mapped_by_id = {}
        for obj in json_objects:
            if obj["type"] == "x-mitre-collection":
                obj["mapipieline_added_labels"] = set()
                mapped_by_id["current-collection_being_loaded"] = self._transform_collection_mappings(obj)
                continue
            try:
                mapped_by_id[obj["id"]]
                raise Exception("dupicliate ids not alllowed: " + mapped_by_id["id"])
            except KeyError:
                pass
            mapped_by_id[obj["id"]] = obj
            self._remove_common_fields(obj)
            self._transform_fields(obj)
            self._add_custom_objects(obj)
            self._add_labels(obj)
        return mapped_by_id
    
    def _transform_collection_mappings(self, mitre_collection):
        id_to_updated_mappings = {}
        for obj in mitre_collection.pop("x_mitre_contents"):
            time_stamp = obj["object_modified"]
            time_stamp = datetime.strptime(time_stamp, "%Y-%m-%dT%H:%M:%S.%fZ")
            time_stamp = time_stamp.replace(tzinfo=timezone.utc).timestamp()
            id_to_updated_mappings[obj["object_ref"]] = time_stamp
        mitre_collection["x_mitre_contents_dictionized"] = id_to_updated_mappings
        mitre_collection["stix_uuid"] = mitre_collection["id"]
        return mitre_collection
            
    # extract out keys, etc, transfomration, not changing keys just restructuring
    def _transform_fields(self, json_obj):
        pass
    def _remove_common_fields(self, json_obj):
        mapping = self.load_mapping_cache(json_obj["type"])
        new_json = {}
        for key in mapping["attributes"]:
            extracted = self.extract_and_delete(json_obj, mapping["attributes"][key])
            if extracted:
                new_json[key] = extracted
        if not json_obj:
            pass
        else:
            raise Exception(new_json["type"] + " why is this not empty: " + str(json_obj))
        
        # put back the data
        for k, v in new_json.items():
            json_obj[k] = v
        
        for k in self.REMOVED_VALUES:
            json_obj.pop(k, None)
    def _add_custom_objects(self, obj):
        try:
            obj["attack_id"] = obj["external_references"][0]["external_id"]
        except KeyError: 
            pass
        try:
            obj["attack_id"] = obj["external_references"][0]["external_id"]
        except KeyError: 
            pass
    
    # extracts and stores custom labels in "mapipieline_added_labels" filed
    # to be later saved in the repository layer
    def _add_labels(self, obj):
        labels = set()
        mapping = self.load_mapping_cache(obj["type"])
        for label_path in mapping["derived_labels"]:
            extracted_labels = self.extract_and_delete(obj, label_path)
            if not extracted_labels:
                continue
            
            # either a list of labels or a singular value
            if not isinstance(extracted_labels, list):
                extracted_labels = [extracted_labels]
            for label in extracted_labels:
                label = lib.constants.clean_label_str(label)
                labels.add(label)
        # try:
            # for kill_chain in obj["kill_chain_phases"]:
                # labels.add(kill_chain["phase_name"].replace("-", ""))
        # except KeyError:
            # pass
        obj["mapipieline_added_labels"] = labels
        pass

    # lazily loads in mappings
    def load_mapping_cache(self, resource_type):
        if resource_type in self.mapping_cache:
            return self.mapping_cache[resource_type]
        
        filepath = os.path.join(self.MAPPING_BASE, resource_type + ".json")
        if not os.path.isfile(filepath):
            raise Exception("Could not find mappings for: " + resource_type)
        with open(filepath, "r") as f:
            self.mapping_cache[resource_type] = json.load(f)
        return self.mapping_cache[resource_type]
    
    # extracts json fileds and deletes it
    def extract_and_delete(self, obj: Union[dict, list], path: str) -> Any:
        """
        Extracts a value from a nested dict/list using a path string and deletes it.

        path format: "key1.[0].key2" means obj['key1'][0]['key2']
        """
        parts = re.split(r'\.(?![^\[]*\])', path)  # split on dots not inside brackets
        current = obj
        parent = None
        last_part = None

        for part in parts:
            parent = current
            last_part = part
            # If this is an index like [0]
            if re.match(r'\[\d+\]', part):
                idx = int(part[1:-1])
                current = current[idx]
            else:
                try:
                    current = current[part]
                except KeyError:
                    return

        # Remove the value from the parent
        if re.match(r'\[\d+\]', last_part):
            idx = int(last_part[1:-1])
            value = parent.pop(idx)
        else:
            value = parent.pop(last_part)

        return value