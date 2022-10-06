"""OID4VP Error Response."""

from marshmallow import fields, EXCLUDE

from .....messaging.models.base import BaseModel, BaseModelSchema


class ErrorResponse(BaseModel):
    """ErrorResponse model."""

    ERROR_INVALID_REQUEST = "invalid_request"
    ERROR_INVALID_SCOPE = "invalid_scope"

    class Meta:
        """ErrorResponse metadata."""

        schema_class = "ErrorResponseSchema"

    def __init__(
        self,
        error: str = None,
        *,
        error_description: str = None,
        error_uri: str = None,
        state: str = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.error = error
        self.error_description = error_description
        self.error_uri = error_uri
        self.state = state


class ErrorResponseSchema(BaseModelSchema):
    """Schema for ErrorResponse."""

    class Meta:
        """ErrorResponseSchema metadata."""

        unknown = EXCLUDE
        model_class = ErrorResponse

    error = fields.Str(required=True, example="invalid_request")
    error_description = fields.Str(required=False)
    error_uri = fields.Str(required=False)
    state = fields.Str(required=False)
