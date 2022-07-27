"""Message type identifiers for Connections."""

from ...didcomm_prefix import DIDCommPrefix

# TODO: replace dummy RFC
SPEC_URI = "https://lab.gematik.de/0999-px-over-http"
PROTOCOL_PREFIX_URI = "https://example.org"
ARIES_PROTOCOL = "px-over-http/0.1"

# Message types
INVITATION_RESPONSE = f"{ARIES_PROTOCOL}/invitation-response"
AUTH_REQUEST = f"{ARIES_PROTOCOL}/auth-request"
AUTH_RESPONSE = f"{ARIES_PROTOCOL}/auth-response"
ACK = f"{ARIES_PROTOCOL}/ack"

PROTOCOL_PACKAGE = "aries_cloudagent.protocols.px_over_http.v0_1"

MESSAGE_TYPES = DIDCommPrefix.qualify_all(
    {
        INVITATION_RESPONSE: (
            f"{PROTOCOL_PACKAGE}.messages.invitation_response.InvitationResponse"
        ),
        AUTH_REQUEST: (f"{PROTOCOL_PACKAGE}.messages.auth_request.AuthRequest"),
        AUTH_RESPONSE: (f"{PROTOCOL_PACKAGE}.messages.auth_response.AuthResponse"),
        ACK: (f"{PROTOCOL_PACKAGE}.messages.ack.Ack"),
    }
)
