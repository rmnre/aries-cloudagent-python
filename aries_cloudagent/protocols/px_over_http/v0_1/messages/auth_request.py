"""Represents a px-over-http auth request message."""

from marshmallow import EXCLUDE, fields

from .....messaging.agent_message import AgentMessage, AgentMessageSchema

from ..message_types import PROTOCOL_PACKAGE, AUTH_REQUEST

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}" + ".handlers.auth_request_handler.AuthRequestHandler"
)


class AuthRequest(AgentMessage):
    """Class representing a px-over-http auth request."""

    class Meta:
        """AuthRequest metadata."""

        handler_class = HANDLER_CLASS
        message_type = AUTH_REQUEST
        schema_class = "AuthRequestSchema"

    def __init__(
        self,
        _id: str = None,
        *,
        presentation_definition: dict = None,
        session: str = None,
        nonce: str = None,
        invitation_msg_id: str = None,
        **kwargs,
    ):
        super().__init__(_id, **kwargs)
        self.presentation_definition = presentation_definition
        self.session = session
        self.nonce = nonce
        self.invitation_msg_id = invitation_msg_id


class AuthRequestSchema(AgentMessageSchema):
    """Schema class for auth request."""

    class Meta:
        """AuthRequestSchema metadata."""

        model_class = AuthRequest
        unknown = EXCLUDE

    presentation_definition = fields.Dict(required=True)
    session = fields.Str(required=True)
    nonce = fields.Str(required=True)
    invitation_msg_id = fields.Str(required=False)
