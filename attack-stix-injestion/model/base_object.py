from neomodel import (db, DoesNotExist, StructuredNode, StringProperty, IntegerProperty,
    RelationshipTo, DateTimeProperty, BooleanProperty, ArrayProperty, RelationshipManager)

from.relationship import Relationship

# extends Stuctured node to allow storage of different versions in Neo4j
class VersionedObject(StructuredNode):
    # temp
    uses = RelationshipTo('VersionedObject', 'USES', model=Relationship)
    mitigates = RelationshipTo('VersionedObject', 'MITIGATES', model=Relationship)
    subtechnique_of = RelationshipTo('VersionedObject', 'SUBTECHNIQUE-OF', model=Relationship)
    detects = RelationshipTo('VersionedObject', 'DETECTS', model=Relationship)
    attributed_to = RelationshipTo('VersionedObject', 'ATTRIBUTED-TO', model=Relationship)
    targets = RelationshipTo('VersionedObject', 'TARGETS', model=Relationship)
    revoked_by = RelationshipTo('VersionedObject', 'REVOKED-BY', model=Relationship)
    
    attack_uuid = StringProperty(unique_index=True,required = True)
    attack_id = StringProperty(required = True)

    next_version = RelationshipTo('VersionedObject', 'NEXT_VERSION')
    def save(self, *args, **kwargs):
        own_uuid = self.attack_uuid
        if own_uuid is None:
            raise "UUID Property Required for Versioned Objects"
        # with db.transaction: 
        not_existed = self.element_id is None
        result = super().save(*args, **kwargs)
        version = kwargs.get("version", "latest")
        # first time saving
        if not_existed:
            # find base model if it already exists
            self.base_model = None
            try:
                self.base_model = BaseObject.nodes.get(uuid=own_uuid)
            except DoesNotExist:
                pass
            
            if self.base_model is None:
                self.base_model = BaseObject()
                for prop_name, weridObject in BaseObject.__all_properties__:
                    # print (weridObject)
                    extractedAttr = getattr(self, prop_name, None)
                    # print("prop_name: " + prop_name + " value: " + str(extractedAttr))
                    if extractedAttr is not None:
                        setattr(self.base_model, prop_name, extractedAttr)
                self.base_model.save()
                self.base_model.start.connect(result)
                self.base_model.latest.connect(result)
            else:
                print("why are we incrementing base model?")
                print(self.element_id)
                # have to verify node is indeed, the latest version
                prev_latest = self.base_model.latest.single()
                self.base_model.latest.disconnect(prev_latest)
                self.base_model.latest.connect(result)
                prev_latest.next_version.connect(result)
        return result
    def getBaseNode(self):
        base = self.base_model
        if base is None:
            # will raise error if not existing
            return BaseObject.nodes.get(uuid=self.attack_uuid)
        return base
    def _updateVersion(base_model):
        base_model
    
# temporary patch for connections
_original_connect = RelationshipManager.connect
def custom_connect(self, node, *args, **kwargs):
    print("custom connect????==================")
    print(self.source_class)
    print(isinstance(self, VersionedObject))
    print(type(node))
    print(isinstance(node, VersionedObject))
    print("================================end")
    # if isinstance(node, VersionedObject):
    #     print(f"Connecting a versioned node: {node}")
    #     return _original_connect(self, node.getBaseNode(), *args, **kwargs)
    # else:
    #     print(f"Connecting a normal node: {node}")
    return _original_connect(self, node, *args, **kwargs)
RelationshipManager.connect = custom_connect


class BaseObject(StructuredNode):
    testing = False
    # transfomred
    uuid = StringProperty(unique_index=True, required=testing)
    # EXTRACTED FIELD
    attack_id = StringProperty(required=testing)
    # created_by_ref = 
    created = DateTimeProperty(required = testing)
    modified = DateTimeProperty(required = testing)
    revoked = BooleanProperty(required = testing)
    external_references = ArrayProperty(StringProperty())
    latest = RelationshipTo('VersionedObject', 'LATEST')
    start = RelationshipTo('VersionedObject', 'EARLIEST')
    # object_marking_refs
    # granular_markings