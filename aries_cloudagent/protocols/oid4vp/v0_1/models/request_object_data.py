"""Represents an oid4vp auth request message."""

from marshmallow import EXCLUDE, fields

from .....messaging.models.base import BaseModel, BaseModelSchema
from .....messaging.valid import URI


class RequestObjectData(BaseModel):
    """Class representing data in an oid4vp request object."""

    class Meta:
        """RequestObjectData metadata."""

        schema_class = "RequestObjectDataSchema"

    def __init__(
        self,
        *,
        client_id: str = None,
        redirect_uri: str = None,
        response_type: str = None,
        response_mode: str = None,
        nonce: str = None,
        presentation_definition_uri: str = None,
        presentation_definition: dict = None,
        scope: str = None,
        invitation_msg_id: str = None,
        **kwargs,
    ):
        super().__init__()
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.response_type = response_type
        self.response_mode = response_mode
        self.nonce = nonce
        self.presentation_definition_uri = presentation_definition_uri
        self.presentation_definition = presentation_definition
        self.scope = scope
        self.invitation_msg_id = invitation_msg_id


class RequestObjectDataSchema(BaseModelSchema):
    """Schema class for request object data."""

    class Meta:
        """RequestObjectDataSchema metadata."""

        model_class = RequestObjectData
        unknown = EXCLUDE

    client_id = fields.Str(
        required=True,
        description="OID client_id",
        example="https://client.example.org",
    )
    redirect_uri = fields.Str(required=False, description="OID redirect_uri", **URI)
    response_type = fields.Str(
        required=True, description="OID response_type", example="vp_token"
    )
    response_mode = fields.Str(
        required=False, description="OID response_mode", example="post"
    )
    nonce = fields.Str(required=True, description="OID nonce", example="n-0S6_WzA2Mj")
    presentation_definition_uri = fields.Str(
        required=False,
        description="URL to retrieve presentation_definition from",
        example=(
            "https://server.example.com/presentationdefs"
            "?ref=idcard_presentation_request"
        ),
    )
    presentation_definition = fields.Dict(required=False)
    scope = fields.Str(required=False)
    invitation_msg_id = fields.Str(required=False)
