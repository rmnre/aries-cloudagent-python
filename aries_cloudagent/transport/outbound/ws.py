"""Websockets outbound transport."""

import logging
from typing import Union

from aiohttp import ClientSession, DummyCookieJar

from ...core.profile import Profile
from ...protocols.px_over_http.v0_1.message_types import ARIES_PROTOCOL as PXHTTP_PROTO

from .base import BaseOutboundTransport, OutboundTransportError


class WsTransport(BaseOutboundTransport):
    """Websockets outbound transport class."""

    schemes = ("ws", "wss")
    is_external = False

    def __init__(self, **kwargs) -> None:
        """Initialize an `WsTransport` instance."""
        super().__init__(**kwargs)
        self.logger = logging.getLogger(__name__)

    async def start(self):
        """Start the outbound transport."""
        self.client_session = ClientSession(cookie_jar=DummyCookieJar(), trust_env=True)
        return self

    async def stop(self):
        """Stop the outbound transport."""
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
        """
        if protocol == PXHTTP_PROTO:
            raise OutboundTransportError("px-over-http via WS is not supported")

        # aiohttp should automatically handle websocket sessions
        async with self.client_session.ws_connect(endpoint, headers=metadata) as ws:
            if isinstance(payload, bytes):
                await ws.send_bytes(payload)
            else:
                await ws.send_str(payload)
