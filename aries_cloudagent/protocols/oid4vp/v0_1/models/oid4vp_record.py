"""OID4VP record."""

from typing import Any, Mapping

from marshmallow import fields, validate

from .....messaging.models.base_record import BaseExchangeRecord, BaseExchangeSchema
from .....messaging.valid import UUIDFour, URI


class OID4VPRecord(BaseExchangeRecord):
    """Represents an OID4VP record."""

    class Meta:
        """OID4VPRecord metadata."""

        schema_class = "OID4VPRecordSchema"

    RECORD_TYPE = "oid4vp"
    RECORD_ID_NAME = "oid4vp_id"
    RECORD_TOPIC = "oid4vp"
    TAG_NAMES = {"connection_id", "pres_ex_id"}

    STATE_INITIAL = "initial"
    STATE_REQUEST_RECEIVED = "request-received"
    STATE_DONE = "done"

    def __init__(
        self,
        *,
        oid4vp_id: str = None,
        state: str = None,
        connection_id: str = None,
        pres_ex_id: str = None,
        client_id: str = None,
        redirect_uri: str = None,
        request_uri: str = None,
        response_type: str = None,
        response_mode: str = None,
        nonce: str = None,
        presentation_definition_url: str = None,
        trace: bool = False,  # backward compat: BaseRecord.FromStorage()
        **kwargs,
    ):
        """Initialize a new OID4VPRecord."""
        super().__init__(oid4vp_id, state, trace=trace, **kwargs)
        self.connection_id = connection_id
        self.pres_ex_id = pres_ex_id
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.request_uri = request_uri
        self.response_type = response_type
        self.response_mode = response_mode
        self.nonce = nonce
        self.presentation_definition_url = presentation_definition_url
        self.trace = trace

    @property
    def oid4vp_id(self) -> str:
        """Accessor for the ID associated with this exchange record."""
        return self._id

    @property
    def record_value(self) -> Mapping:
        """Accessor for the JSON record value generated for this credential exchange."""
        return {
            **{
                prop: getattr(self, prop)
                for prop in (
                    "connection_id",
                    "pres_ex_id",
                    "client_id",
                    "redirect_uri",
                    "request_uri",
                    "response_type",
                    "response_mode",
                    "nonce",
                    "presentation_definition_url",
                    "state",
                    "trace",
                )
            },
        }

    def __eq__(self, other: Any) -> bool:
        """Comparison between records."""
        return super().__eq__(other)


class OID4VPRecordSchema(BaseExchangeSchema):
    """Schema for de/serialization of OID4VP records."""

    class Meta:
        """OID4VPRecordSchema metadata."""

        model_class = OID4VPRecord

    oid4vp_id = fields.Str(
        required=False,
        description="OID4VP record identifier",
        example=UUIDFour.EXAMPLE,  # typically a UUID4 but not necessarily
    )
    connection_id = fields.Str(
        required=False,
        description="Connection identifier",
        example=UUIDFour.EXAMPLE,  # typically a UUID4 but not necessarily
    )
    pres_ex_id = fields.Str(
        required=False,
        description="Presentation exchange identifier",
        example=UUIDFour.EXAMPLE,  # typically a UUID4 but not necessarily
    )
    client_id = fields.Str(
        required=False,
        description="OID client_id",
        example="https://client.example.org",
    )
    redirect_uri = fields.Str(required=False, description="OID redirect_uri", **URI)
    request_uri = fields.Str(required=False, description="OID request_uri", **URI)
    response_type = fields.Str(
        required=False, description="OID response_type", example="vp_token"
    )
    response_mode = fields.Str(
        required=False, description="OID response_mode", example="post"
    )
    nonce = fields.Str(required=False, description="OID nonce", example="n-0S6_WzA2Mj")
    presentation_definition_url = fields.Str(
        required=False,
        description="URL to retrieve presentation_definition from",
        example=(
            "https://server.example.com/presentationdefs"
            "?ref=idcard_presentation_request"
        ),
    )
    state = fields.Str(
        required=False,
        description="exchange state",
        validate=validate.OneOf(
            [
                getattr(OID4VPRecord, m)
                for m in vars(OID4VPRecord)
                if m.startswith("STATE_")
            ]
        ),
    )
