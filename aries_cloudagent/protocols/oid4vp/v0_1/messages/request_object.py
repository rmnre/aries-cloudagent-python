"""Represents an OID request object."""

from marshmallow import fields, EXCLUDE

from .....messaging.agent_message import AgentMessage, AgentMessageSchema
from .....messaging.valid import UUID4

from ..message_types import PROTOCOL_PACKAGE, REQUEST_OBJECT

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}" + ".handlers.request_object_handler.RequestObjectHandler"
)


class RequestObject(AgentMessage):
    """Class representing an oid request object."""

    class Meta:
        """RequestObject metadata."""

        handler_class = HANDLER_CLASS
        message_type = REQUEST_OBJECT
        schema_class = "RequestObjectSchema"

    def __init__(
        self,
        _id: str = None,
        *,
        value: str = None,
        invitation_msg_id: str = None,
        **kwargs,
    ):
        super().__init__(_id, **kwargs)
        self.value = value
        self.invitation_msg_id = invitation_msg_id


class RequestObjectSchema(AgentMessageSchema):
    """Schema class for request object."""

    class Meta:
        """RequestObjectSchema metadata."""

        model_class = RequestObject
        unknown = EXCLUDE

    value = fields.Str(required=False, description="The JWT")
    invitation_msg_id = fields.Str(required=False, **UUID4)
