"""Represents a px-over-http invitation response message."""

from marshmallow import EXCLUDE, fields

from .....messaging.agent_message import AgentMessage, AgentMessageSchema
from .....messaging.valid import UUIDFour

from ..message_types import INVITATION_RESPONSE

HANDLER_CLASS = None


class InvitationResponse(AgentMessage):
    """Class representing a px-over-http invitation response."""

    class Meta:
        """Metadata for px-over-http invitation response."""

        handler_class = HANDLER_CLASS
        message_type = INVITATION_RESPONSE
        schema_class = "InvitationResponseSchema"

    def __init__(
        self,
        *,
        invitation_msg_id: str = None,
        **kwargs,
    ):
        """
        Initialize invitation response object.

        Args:
            invitation_msg_id: Invitation message id
        """
        super().__init__(**kwargs)
        self.invitation_msg_id = invitation_msg_id


class InvitationResponseSchema(AgentMessageSchema):
    """Schema class for invitation response."""

    class Meta:
        """invitation response schema class metadata."""

        model_class = InvitationResponse
        unknown = EXCLUDE

    invitation_msg_id = fields.Str(
        description="Invitation msg id", example=UUIDFour.EXAMPLE
    )
