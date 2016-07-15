from marshmallow import Schema, fields


class MetaSchema(Schema):
    class Meta:
        ordered = True

    key = fields.String(required=True)
    name = fields.String(required=True)
