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
            self._derive_attributes(obj)
            self._add_labels(obj)
            self._transform_fields(obj)
            self._remove_common_fields(obj)
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
    
    def _derive_attributes(self, json_obj):
        mapping = self.load_mapping_cache(json_obj["type"])
        for att_name, att_path in mapping["derived_attributes"].items():
            try:
                extracted = self._extract(json_obj, att_path)
            except KeyError:
                continue
            json_obj[att_name] = extracted
            
    # extract out keys, etc, transfomration, not changing keys just restructuring
    def _transform_fields(self, json_obj):
        obj_type = json_obj["type"]
        mapping = self.load_mapping_cache(obj_type)
        new_json = {}
        for key in mapping["attributes"]:
            # greedily match mappings
            try:
                extracted = self._extract(json_obj, mapping["attributes"][key], True)
                new_json[key] = extracted
            except KeyError:
                pass
        new_json["mapipieline_added_labels"] = json_obj.pop("mapipieline_added_labels")
        if json_obj:
            raise Exception(obj_type + " why is this not empty: " + str(json_obj))
        
        # put back the data
        for k, v in new_json.items():
            json_obj[k] = v
    def _remove_common_fields(self, json_obj):
        for k in self.REMOVED_VALUES:
            json_obj.pop(k, None)
    
    # extracts and stores custom labels in "mapipieline_added_labels" filed
    # to be later saved in the repository layer
    def _add_labels(self, obj):
        labels = set()
        print("addinglabels for : " + obj["id"])
        print(obj)
        print("before")
        mapping = self.load_mapping_cache(obj["type"])
        for label_path in mapping["derived_labels"]:
            try:
                extracted_labels = self._extract(obj, label_path)
            except KeyError:
                continue
            
            # either a list of labels or a singular value
            if not isinstance(extracted_labels, list):
                extracted_labels = [extracted_labels]
            for label in extracted_labels:
                label = lib.constants.clean_label_str(label)
                labels.add(label)
        obj["mapipieline_added_labels"] = labels
        print("after")

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
    
    def _extract(self, json_obj, path, toDelete=False):
        if path == "[*]":
            raise Exception("Invalid Path")
        filtered_path = path.split(".")
        return self._recursive_json_dig(None, filtered_path, json_obj, 0, toDelete)
    def _recursive_json_dig(self, parent, operations, jsonobj, iterator, toDelete):
        op = operations[iterator]

        if not (op[0] == "[" and op[-1] == "]"):
            if iterator == len(operations) - 1:
                return jsonobj[op] if not toDelete else jsonobj.pop(op)
            return self._recursive_json_dig(jsonobj, operations, jsonobj[op], iterator + 1, toDelete)
        index = op[1:len(op) - 1]
        if index == "*":
            if iterator == len(operations) - 1:
                if toDelete:
                    op = operations[iterator - 1]
                    if not (op[0] == "[" and op[-1] == "]"):
                        return parent.pop(op)
                    if not op == "*":
                        return parent.pop(int(op))
                
                # so nice
                return jsonobj
                # very nice
            combined = []
            for elem in jsonobj:
                dig_result = self._recursive_json_dig(jsonobj, operations, elem, iterator + 1, toDelete)
                if not isinstance(dig_result, list):
                    dig_result = [dig_result]
                combined = combined + dig_result
            return combined
        else:
            if iterator == len(operations) - 1:
                return jsonobj[int(index)] if not toDelete else jsonobj.pop(int(index))
            return self._recursive_json_dig(jsonobj, operations, jsonobj[int(index)], iterator + 1, toDelete)