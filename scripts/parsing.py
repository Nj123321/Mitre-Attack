# hacky shared lib solution
import sys, os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)
# hacky solution --- end

import json
import stix2
import time

fn = "attack-stix-data/mobile-attack/mobile-attack.json"
fn = "attack-stix-data/enterprise-attack/enterprise-attack.json"
fn = "attack-stix-injestion/resources/mitre-attack-data/enterprise-attack/enterprise-attack.json"

import os

import lib.constants

project_base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
print(project_base)
fn = project_base + "/attack-stix-injestion/resources/mitre-attack-data/enterprise-attack/enterprise-attack.json"

creating_new_mappings = False

with open(fn, "r", encoding="utf-8") as f:
    bundle_dict = json.load(f)

# Parse into a Bundle object (and parse contained objects into STIX SDO/SROs)
bundle = stix2.parse(bundle_dict, version="2.1", allow_custom=True)
stix2.Filter

# bundle is a stix2 Bundle object; bundle.objects is a list of stix2 objects
countz = {}



# graph = Graph("bolt://localhost:7687")

id_mapping = {}
print("Bundle contains", len(bundle.objects), "objects")
for obj in bundle.objects:
    name = obj.__class__.__name__
    if name == "dict":
        name = obj["type"]
    if not isinstance(obj, dict):
        obj = obj.__dict__['_inner']
        name = obj['type']
    
    try:
        id_mapping[name]
    except KeyError:
        id_mapping[name] = []
    # print("whatthefuck: " + id_mapping[name].ser)
    id_mapping[name].append(obj)
    
for k, v in id_mapping.items():
    print("k: " + str(k) + "   |  length: " + str(len(v)))

# intialize keys to look for
keys_to_look_for = set(["woop"])
keys_to_look_for_hash = {}
for key in keys_to_look_for:
    keys_to_look_for_hash[key] = set()
    
intersection = set()

bad_model = [
    "marking-definition",
    "relationship",
]

# find attirbutes per model
att_to_look = ["x_mitre_platforms"]

# mappings
bad_att = [
    ""
]
import os
directory = "/Users/nathan.jin/Desktop/work/mitreattack/attack-stix-injestion/resources/mappings/"

# pre-compute intersection
for name, obj_array in id_mapping.items():
    attribute_value_collector = {}
    for att in att_to_look:
        attribute_value_collector[att] = set()
    common_attributes = set()
    first = True
    for elem in obj_array:
        for keys in elem:
            if not keys in common_attributes:
                if first:
                    common_attributes.add(keys)
                else:
                    try:
                        common_attributes.remove(keys)
                    except KeyError:
                        pass
        if first:
            first = False
    if name in bad_model:
        continue
    # if name.startswith("x-mitre"):
        # continue
    print("DEBUG - intersection: " + name)
    if len(intersection) == 0:
        intersection = common_attributes
    else:
        intersection = intersection.intersection(common_attributes)

common_labels = [""]

for name, obj_array in id_mapping.items():
    print("======================" + name)
    # mappings
    file_path = os.path.join(directory, name + ".json")
    mapping_creator = {}
    mapping_creator["delete"] = []
    mapping_creator["attributes"] = {}
    mapping_creator["derived_relatinoships"] = {}
    mapping_creator["derived_labels"] = []
    
    attribute_value_collector = {}
    for att in att_to_look:
        attribute_value_collector[att] = set()
    
    attributez = set()
    common_attributes = set()
    first = True
    for elem in obj_array:
        for keys in elem:
            if keys in keys_to_look_for:
                keys_to_look_for_hash[keys].add(name)
            # total aggregator
            attributez.add(keys)
            # local aggregator
            if not keys in common_attributes:
                if first:
                    common_attributes.add(keys)
                else:
                    try:
                        common_attributes.remove(keys)
                    except KeyError:
                        pass
            if keys in att_to_look:
                found_values = elem[keys]
                if not isinstance(found_values, list):
                    found_values = [found_values]
                for value in found_values:
                    value = lib.constants.clean_label_str(value)
                    attribute_value_collector[keys].add(value)
            # global aggregator / intersector
        elem
        if first:
            first = False
    print("COLLECTED: ")
    for k in att_to_look:
        if len(attribute_value_collector[k]) == 0:
            attribute_value_collector.pop(k)
    print(attribute_value_collector)
    
    
    
    attributez = attributez.difference(intersection)
    common_attributes = common_attributes.difference(intersection)
    print("TOTAL ATTRIBUTES: ")
    temp = list(attributez)
    temp.sort()
    print(temp)
    
    total_att = temp
    
    print("COMMON ATTRIBUTES: ")
    temp = list(common_attributes)
    temp.sort()
    print(temp)
    
    # build mapping
    for att in total_att:
        if att in bad_att:
            mapping_creator["delete"].append(att)
        else:
            mapping_creator["attributes"][att] = att
    if creating_new_mappings:
        with open(file_path, "w") as f:
            json.dump(mapping_creator, f, indent=4)
        print("created mappings for: " + file_path)
            
    if name in bad_model:
        print("=======end===============")
        continue
    # if name.startswith("x-mitre"):
        # print("=======end===============")
        # continue
    print("=======end===============")
    # if name == "Relationship":
        # knows = Relationship(id_mapping[obj.source_ref], obj.relationship_type, id_mapping[obj.target_ref])
        # graph.create(knows)
    # else:
        # n = Node(obj_json["type"], **obj_json)
        # id_mapping[id] = n
        # graph.create(n)
# for k,v in keys_to_look_for_hash:
#     print("foundkey: " + k)
#     print("for:")
#     print(v)
temp = list(intersection)
temp.sort()
print(temp)

    # print(obj["type"], obj["id"], getattr(obj, "name", None))

# catcher = set()
# for name, obj_array in id_mapping.items():
#     for obj in obj_array:
#         try:
#             for keychain in obj["kill_chain_phases"]:
#                 catcher.add(keychain["phase_name"].replace("-", ""))
#         except KeyError:
#             pass
# print("------")
# print(catcher)

# catcher = set()
# first = True
# for name, obj_array in id_mapping.items():
#     for obj in obj_array:
#         for k, v in obj_array:
#             if first:
#                 catcher.add(k)
#             else:
#                 for names in catcher:
#                     try:
#                         obj_array[names]
#                     except KeyError:
#                         catcher.remove(names)
#         if first:
#             first= False
# print("------")
# print(catcher)


# obj = {"type": "malware", "id": "malware--2", "name": "Emotet"}
# node = Node(obj["type"], **obj)  # label = "malware", dynamic
# graph.create(node)