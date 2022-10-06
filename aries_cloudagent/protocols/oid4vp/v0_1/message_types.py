"""Message type identifiers for oid4vp."""

from ...didcomm_prefix import DIDCommPrefix

# TODO: replace dummy RFC
SPEC_URI = "https://lab.gematik.de/0888-oid4vp"
PROTOCOL_PREFIX_URI = "https://example.org"
ARIES_PROTOCOL = "oid4vp/0.1"
HANDSHAKE_PROTOCOL = "oid4vp-handshake/0.1"

# Message types
REQUEST_OBJECT = f"{ARIES_PROTOCOL}/request-object"

PROTOCOL_PACKAGE = "aries_cloudagent.protocols.oid4vp.v0_1"

MESSAGE_TYPES = DIDCommPrefix.qualify_all(
    {
        REQUEST_OBJECT: (f"{PROTOCOL_PACKAGE}.messages.request_object.RequestObject"),
    }
)
