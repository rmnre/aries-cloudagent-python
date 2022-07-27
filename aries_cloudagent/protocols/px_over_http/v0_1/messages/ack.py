"""Represents an explicit RFC 15 ack message, adopted into px-over-http protocol."""

from marshmallow import EXCLUDE, fields

from ....notification.v1_0.messages.ack import V10Ack, V10AckSchema

from ..message_types import ACK, PROTOCOL_PACKAGE

HANDLER_CLASS = f"{PROTOCOL_PACKAGE}.handlers.ack_handler.AckHandler"


class Ack(V10Ack):
    """Base class representing an explicit ack message for px-over-http protocol."""

    class Meta:
        """Ack metadata."""

        handler_class = HANDLER_CLASS
        message_type = ACK
        schema_class = "AckSchema"

    def __init__(self, status: str = None, session: str = None, **kwargs):
        """
        Initialize an explicit ack message instance.

        Args:
            status: Status (default OK)
            session: session identifier

        """
        super().__init__(status, **kwargs)
        self.session = session


class AckSchema(V10AckSchema):
    """Schema for Ack class."""

    class Meta:
        """Ack schema metadata."""

        model_class = Ack
        unknown = EXCLUDE

    session = fields.Str(required=False, description="session identifier")
