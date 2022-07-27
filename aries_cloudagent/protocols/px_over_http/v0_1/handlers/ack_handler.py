"""px-over-http ack message handler."""

from .....messaging.base_handler import BaseHandler, HandlerException
from .....messaging.request_context import RequestContext
from .....messaging.responder import BaseResponder

# from .....utils.tracing import trace_event, get_timer

from ..manager import PXHTTPManager, PXHTTPManagerError
from ..messages.ack import Ack


class AckHandler(BaseHandler):
    """Message handler class for auth response acks."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Message handler logic for auth response acks.

        Args:
            context: request context
            responder: responder callback
        """
        # r_time = get_timer()

        self._logger.debug("AckHandler called with context %s", context)
        assert isinstance(context.message, Ack)
        self._logger.info(
            "Received auth response ack message: %s",
            context.message.serialize(as_string=True),
        )

        pxhttp_manager = PXHTTPManager(context.profile)
        try:
            await pxhttp_manager.receive_ack(context.message)
        except PXHTTPManagerError as err:
            raise HandlerException("Error receiving Ack message.") from err

        # trace_event(
        #     context.settings,
        #     context.message,
        #     outcome="V20PresAckHandler.handle.END",
        #     perf_counter=r_time,
        # )
