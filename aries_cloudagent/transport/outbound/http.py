"""Http outbound transport."""

import json
import logging

from aiohttp import ClientSession, ContentTypeError, DummyCookieJar, TCPConnector
from json import JSONDecodeError
from typing import Union

from ...core.profile import Profile
from ...messaging.models.base import BaseModelError
from ...protocols.oid4vp.v0_1.message_types import ARIES_PROTOCOL as OID4VP_PROTO
from ...protocols.oid4vp.v0_1.messages.request_object import (
    RequestObject as OID4VPRequestObject,
)
from ...protocols.px_over_http.v0_1.message_types import ARIES_PROTOCOL as PXHTTP_PROTO
from ...protocols.px_over_http.v0_1.messages.auth_request import (
    AuthRequest as PXHTTPAuthRequest,
)
from ...protocols.px_over_http.v0_1.messages.ack import Ack as PXHTTP_ACK
from ...transport.inbound.manager import InboundTransportManager

from ..stats import StatsTracer
from ..wire_format import DIDCOMM_V0_MIME_TYPE, DIDCOMM_V1_MIME_TYPE, JsonWireFormat

from .base import BaseOutboundTransport, OutboundTransportError


class HttpTransport(BaseOutboundTransport):
    """Http outbound transport class."""

    schemes = ("http", "https")
    is_external = False

    def __init__(self, **kwargs) -> None:
        """Initialize an `HttpTransport` instance."""
        super().__init__(**kwargs)
        self.client_session: ClientSession = None
        self.connector: TCPConnector = None
        self.logger = logging.getLogger(__name__)

    async def start(self):
        """Start the transport."""
        self.connector = TCPConnector(limit=200, limit_per_host=50)
        session_args = {
            "cookie_jar": DummyCookieJar(),
            "connector": self.connector,
            "trust_env": True,
        }
        if self.collector:
            session_args["trace_configs"] = [
                StatsTracer(self.collector, "outbound-http:")
            ]
        self.client_session = ClientSession(**session_args)
        return self

    async def stop(self):
        """Stop the transport."""
        await self.client_session.close()
        self.client_session = None

    async def handle_message(
        self,
        profile: Profile,
        payload: Union[str, bytes],
        endpoint: str,
        metadata: dict = None,
        protocol: str = None,
        api_key: str = None,
    ):
        """
        Handle message from queue.

        Args:
            profile: the profile that produced the message
            payload: message payload in string or byte format
            endpoint: URI endpoint for delivery
            metadata: Additional metadata associated with the payload
            protocol: protocol used for message delivery
        """
        if protocol == PXHTTP_PROTO:
            return await self.handle_message_pxhttp(
                profile, payload, endpoint, metadata, api_key
            )
        elif protocol == OID4VP_PROTO:
            return await self.handle_message_oid4vp(
                profile, payload, endpoint, metadata, api_key
            )

        if not endpoint:
            raise OutboundTransportError("No endpoint provided")
        headers = metadata or {}
        if api_key is not None:
            headers["x-api-key"] = api_key
        if isinstance(payload, bytes):
            if profile.settings.get("emit_new_didcomm_mime_type"):
                headers["Content-Type"] = DIDCOMM_V1_MIME_TYPE
            else:
                headers["Content-Type"] = DIDCOMM_V0_MIME_TYPE
        else:
            headers["Content-Type"] = "application/json"
        self.logger.debug(
            "Posting to %s; Data: %s; Headers: %s", endpoint, payload, headers
        )
        async with self.client_session.post(
            endpoint, data=payload, headers=headers
        ) as response:
            if response.status < 200 or response.status > 299:
                raise OutboundTransportError(
                    (
                        f"Unexpected response status {response.status}, "
                        f"caused by: {response.reason}"
                    )
                )

    async def handle_message_pxhttp(
        self,
        profile: Profile,
        payload: Union[str, bytes],
        endpoint: str,
        metadata: dict = None,
        api_key: str = None,
    ):
        """
        Handle message from queue.

        Args:
            profile: the profile that produced the message
            payload: message payload in string or byte format
            endpoint: URI endpoint for delivery
            metadata: Additional metadata associated with the payload
        """
        if not endpoint:
            raise OutboundTransportError("No endpoint provided")
        if isinstance(payload, bytes):
            raise OutboundTransportError(
                "Payload in byte format is not supported "
                "for outgoing messages via px-over-http."
            )
        headers = metadata or {}
        headers["Content-Type"] = "application/json"
        if api_key is not None:
            headers["x-api-key"] = api_key
        out_message: dict = json.loads(payload)

        self.logger.debug(
            "Posting to %s; Data: %s; Headers: %s", endpoint, payload, headers
        )
        async with self.client_session.post(
            endpoint, data=payload, headers=headers
        ) as resp:
            if resp.status != 200:
                raise OutboundTransportError(
                    (
                        f"Unexpected response status {resp.status}, "
                        f"caused by: {resp.reason}"
                    )
                )

            if resp.content_type == "application/octet-stream":
                response = {}
            else:
                try:
                    response = await resp.json()
                except ContentTypeError as err:
                    raise OutboundTransportError(
                        "Expected JSON response but "
                        f"content type was {resp.content_type}."
                    ) from err
                except JSONDecodeError as err:
                    raise OutboundTransportError(
                        "Received response is not valid JSON."
                    ) from err

        # construct protocol message
        if "invitation_msg_id" in out_message and "presentation_definition" in response:
            # TODO: use Schema.validate?
            # receive auth request
            try:
                response_msg: PXHTTPAuthRequest = PXHTTPAuthRequest.deserialize(
                    response
                )
                # add invitation_msg_id as reference to conn record
                response_msg.invitation_msg_id = out_message["invitation_msg_id"]
            except BaseModelError as err:
                raise OutboundTransportError("Received invalid auth request.") from err

        elif "session" in out_message and not response:
            # auth response ack
            response_msg = PXHTTP_ACK(session=out_message["session"])
        else:
            raise OutboundTransportError(f"Unexpected message payload: {response}")

        # pass message to inbound handler
        inbound_mgr = profile.inject(InboundTransportManager)
        session = await inbound_mgr.create_session(
            transport_type=None,
            wire_format=JsonWireFormat(),
        )
        async with session:
            await session.receive(response_msg.to_json())

        self.logger.debug(
            "Received response to POST request as inbound message: %s", response
        )

    async def handle_message_oid4vp(
        self,
        profile: Profile,
        payload: Union[str, bytes],
        endpoint: str,
        metadata: dict = None,
        api_key: str = None,
    ):
        """
        Handle message from queue.

        Args:
            profile: the profile that produced the message
            payload: message payload in string or byte format
            endpoint: URI endpoint for delivery
            metadata: Additional metadata associated with the payload
        """
        if not endpoint:
            raise OutboundTransportError("No endpoint provided")
        if not payload:
            raise OutboundTransportError(
                "No payload provided for oid4vp outbound message."
            )
        if isinstance(payload, bytes):
            raise OutboundTransportError(
                "Payload in byte format is not supported "
                "for outgoing messages via oid4vp."
            )
        headers = metadata or {}
        if api_key is not None:
            headers["x-api-key"] = api_key
        out_msg: dict = json.loads(payload)
        in_msg = None

        if "invitation_msg_id" in out_msg:
            # get request object from request_uri
            self.logger.debug("GET %s; Headers: %s", endpoint, headers)
            async with self.client_session.get(endpoint, headers=headers) as resp:
                if resp.status != 200:
                    raise OutboundTransportError(
                        (
                            f"Unexpected response status {resp.status}, "
                            f"caused by: {resp.reason}"
                        )
                    )

                try:
                    response = await resp.text()
                except LookupError as err:
                    raise OutboundTransportError(
                        "Unknown text encoding used in HTTP response"
                    ) from err

            # construct protocol message
            # add invitation_msg_id as reference to conn record
            in_msg: OID4VPRequestObject = OID4VPRequestObject(
                value=response, invitation_msg_id=out_msg["invitation_msg_id"]
            )

        else:
            # TODO: only works for response_mode POST

            # workaround for correct form-encoding of nested dict
            for k, v in out_msg.items():
                if isinstance(v, dict):
                    out_msg[k] = json.dumps(v)

            async with self.client_session.post(
                endpoint, data=out_msg, headers=headers
            ) as resp:
                if resp.status != 200:
                    raise OutboundTransportError(
                        (
                            f"Unexpected response status {resp.status}, "
                            f"caused by: {resp.reason}"
                        )
                    )

                if resp.content_type == "application/octet-stream":
                    response = {}
                else:
                    try:
                        response = await resp.json()
                    except ContentTypeError as err:
                        raise OutboundTransportError(
                            "Expected JSON response but "
                            f"content type was {resp.content_type}."
                        ) from err
                    except JSONDecodeError as err:
                        raise OutboundTransportError(
                            "Received response is not valid JSON."
                        ) from err

        if in_msg:
            # pass message to inbound handler
            inbound_mgr = profile.inject(InboundTransportManager)
            session = await inbound_mgr.create_session(
                transport_type=None,
                wire_format=JsonWireFormat(),
            )
            async with session:
                await session.receive(in_msg.to_json())

            self.logger.debug(
                "Received response to outbound request as inbound message: %s", response
            )
