from neomodel import (db, DoesNotExist, StructuredNode, StringProperty, IntegerProperty,
    RelationshipTo, DateTimeProperty, BooleanProperty, ArrayProperty, RelationshipManager)


class MitreBase:
    attack_taxonomy = StringProperty(required = True)
    