"""px-over-http auth request handler."""

import json

from .....connections.models.conn_record import ConnRecord
from .....connections.models.connection_target import ConnectionTarget
from .....indy.holder import IndyHolderError
from .....ledger.error import LedgerError
from .....messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    HandlerException,
    RequestContext,
)
from .....messaging.decorators.attach_decorator import AttachDecorator
from .....messaging.models.base import BaseModelError
from .....storage.error import StorageError, StorageNotFoundError
from .....wallet.error import WalletNotFoundError

from ....present_proof.v2_0.formats.handler import V20PresFormatHandlerError
from ....present_proof.v2_0.manager import (
    V20PresManager,
    V20PresManagerError,
)
from ....present_proof.v2_0.message_types import ATTACHMENT_FORMAT, PRES_20_REQUEST
from ....present_proof.v2_0.messages.pres_format import V20PresFormat
from ....present_proof.v2_0.messages.pres_request import V20PresRequest
from ....present_proof.v2_0.models.pres_exchange import (
    V20PresExRecord,
)

from ..message_types import ARIES_PROTOCOL as PXHTTP_PROTO
from ..messages.auth_request import AuthRequest as PXHTTPAuthRequest
from ..manager import PXHTTPManager


class AuthRequestHandler(BaseHandler):
    """Handler class for px-over-http auth request message."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Handle px-over-http auth request.

        Args:
            context: Request context
            responder: Responder callback
        """
        self._logger.debug("AuthRequestHandler called with context %s", context)
        assert isinstance(context.message, PXHTTPAuthRequest)
        profile = context.profile
        auth_request = context.message
        invitation_msg_id = auth_request.invitation_msg_id

        tag_filter = {"invitation_msg_id": invitation_msg_id}
        post_filter = {
            "state": ConnRecord.State.REQUEST.rfc160,
            "their_role": ConnRecord.Role.RESPONDER.rfc160,
        }
        async with profile.session() as session:
            conn_record = await ConnRecord.retrieve_by_tag_filter(
                session,
                tag_filter,
                post_filter,
            )
            if not conn_record:
                raise HandlerException(
                    "No connection record found for invitation message id "
                    f"{invitation_msg_id}"
                )
            conn_record.state = ConnRecord.State.COMPLETED.rfc23
            await conn_record.save(session, reason="Set connection state to completed")
            invitation = await conn_record.retrieve_invitation(session)

        # not checking for None as already done during receive_invitation
        pxhttp_endpoint = PXHTTPManager.get_endpoint_from_invitation(invitation)
        pres_request_message = V20PresRequest(
            comment="auto-created pres request from auth request",
            will_confirm=False,
            formats=[
                V20PresFormat(
                    attach_id="auth_request",
                    format_=ATTACHMENT_FORMAT[PRES_20_REQUEST][
                        V20PresFormat.Format.DIF.api
                    ],
                )
            ],
            request_presentations_attach=[
                AttachDecorator.data_json(
                    {
                        "options": {
                            "challenge": auth_request.nonce,
                            "domain": pxhttp_endpoint,
                        },
                        "presentation_definition": (
                            auth_request.presentation_definition
                        ),
                    },
                    ident="auth_request",
                )
            ],
        )

        pres_ex_record = V20PresExRecord(
            connection_id=conn_record.connection_id,
            thread_id=pres_request_message._thread_id,
            initiator=V20PresExRecord.INITIATOR_EXTERNAL,
            role=V20PresExRecord.ROLE_PROVER,
            pres_request=pres_request_message,
            auto_present=context.settings.get(
                "debug.auto_respond_presentation_request"
            ),
            trace=(pres_request_message._trace is not None),
            pxhttp_session=auth_request.session,
        )
        pres_mgr = V20PresManager(profile)
        try:
            await pres_mgr.receive_pres_request(pres_ex_record)
        except V20PresManagerError as e:
            self._logger.exception("Error receiving auth request")
            raise HandlerException(e.roll_up)

        # If auto_present is enabled, respond immediately with presentation
        if pres_ex_record.auto_present:
            if not auth_request.presentation_definition.get("input_descriptors"):
                raise HandlerException(
                    "Cannot auto-respond to auth request with no input descriptors "
                    "in presentation definition."
                )

            pres_message = None
            try:
                (pres_ex_record, pres_message) = await pres_mgr.create_pres(
                    pres_ex_record=pres_ex_record,
                    comment=(
                        f"auto-presented for proof requests"
                        f", pres_ex_record: {pres_ex_record.pres_ex_id}"
                    ),
                )
                pxhttp_mgr = PXHTTPManager(profile)
                auth_response = pxhttp_mgr.create_response(
                    pres=pres_message, session=auth_request.session
                )
                # transform response to string so responder does not add
                # DIDComm parameters via Schema.dump
                reply = json.dumps(
                    {
                        "id_token": auth_response.id_token,
                        "session": auth_response.session,
                    }
                )
                async with profile.session() as session:
                    invitation = await conn_record.retrieve_invitation(session)

                # not checking for None as already done during receive_invitation
                pxhttp_endpoint = PXHTTPManager.get_endpoint_from_invitation(invitation)
                target = ConnectionTarget(endpoint=pxhttp_endpoint)
                await responder.send_reply(reply, target=target, protocol=PXHTTP_PROTO)
            except (
                BaseModelError,
                IndyHolderError,
                LedgerError,
                StorageError,
                StorageNotFoundError,
                WalletNotFoundError,
                V20PresFormatHandlerError,
            ) as err:
                self._logger.exception(err)
                if pres_ex_record:
                    async with profile.session() as session:
                        await pres_ex_record.save_error_state(
                            session,
                            reason=err.roll_up,
                        )
