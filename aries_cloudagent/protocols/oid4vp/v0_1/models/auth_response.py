"""OID4VP Auth Response."""

from marshmallow import fields, EXCLUDE

from .....messaging.models.base import BaseModel, BaseModelSchema

from ....present_proof.dif.pres_exch import (
    PresentationSubmission,
    PresentationSubmissionSchema,
)


class AuthResponse(BaseModel):
    """AuthResponse model."""

    class Meta:
        """AuthResponse metadata."""

        schema_class = "AuthResponseSchema"

    def __init__(
        self,
        *,
        vp_token: dict = None,
        presentation_submission: PresentationSubmission = None,
        id_token: dict = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.vp_token = vp_token
        self.presentation_submission = presentation_submission
        self.id_token = id_token


class AuthResponseSchema(BaseModelSchema):
    """Schema for AuthResponse."""

    class Meta:
        """AuthResponseSchema metadata."""

        unknown = EXCLUDE
        model_class = AuthResponse

    vp_token = fields.Dict(
        required=False, description="vp_token containing verifiable presentation(s)"
    )
    presentation_submission = fields.Nested(
        PresentationSubmissionSchema,
        required=False,
    )
    id_token = fields.Dict(required=False, description="OIDC id_token")
