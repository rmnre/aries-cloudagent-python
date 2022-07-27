"""Represents a px-over-http auth response message."""

from marshmallow import EXCLUDE, fields

from .....messaging.agent_message import AgentMessage, AgentMessageSchema

from ..message_types import AUTH_RESPONSE

HANDLER_CLASS = None


class AuthResponse(AgentMessage):
    """Class representing a px-over-http auth response."""

    class Meta:
        """Metadata for px-over-http auth response."""

        handler_class = HANDLER_CLASS
        message_type = AUTH_RESPONSE
        schema_class = "AuthResponseSchema"

    def __init__(
        self,
        *,
        id_token: str = None,
        session: str = None,
        **kwargs,
    ):
        """
        Initialize auth response object.

        Args:
            id_token: contains a jwt_vp
            session: session identifier
        """
        super().__init__(**kwargs)
        self.id_token = id_token
        self.session = session


class AuthResponseSchema(AgentMessageSchema):
    """Schema class for auth response."""

    class Meta:
        """auth response schema class metadata."""

        model_class = AuthResponse
        unknown = EXCLUDE

    id_token = fields.Str(required=False)
    session = fields.Str(required=False)
