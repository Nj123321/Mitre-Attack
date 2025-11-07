# handles json logic / field extraction / labels
# takes in hashes as inputs

# stores filters? as jsons? if time? parse based on jsons / transfomrs jsons 
# dyanmcailly creates filters based on class name -> file mapping
class Parser:
    REMOVED_VALUES = ["object_marking_refs"]
    def __init__(self):
        print("initilaizing parser")
    def parse_data(self, json_objects):
        for obj in json_objects:
            print(obj)
            self._remove_common_fields(obj)
            self._transform_fields(obj)
            self._map_to_database_keys(obj)
            self._add_custom_objects(obj, json_objects)
            self._add_labels(obj)
        return json_objects
    # extract out keys, etc, transfomration, not changing keys just restructuring
    def _transform_fields(self, json_obj):
        pass
    def _remove_common_fields(self, json_obj):
        for k in self.REMOVED_VALUES:
            json_obj.pop(k, None)
    def _map_to_database_keys(self, json_obj):
        json_obj["attack_uuid"] = json_obj["id"]
        json_obj.pop("id")
    def _add_custom_objects(self, obj, json_objects):
        try:
            obj["attack_id"] = obj["external_references"][0]["external_id"]
        except KeyError: 
            pass
        try:
            obj["attack_id"] = obj["external_references"][0]["external_id"]
        except KeyError: 
            pass
    def _add_labels(self, obj):
        labels = set()
        try:
            for kill_chain in obj["kill_chain_phases"]:
                labels.add(kill_chain["phase_name"].replace("-", ""))
        except KeyError:
            pass
        obj["mapipieline_added_labels"] = labels