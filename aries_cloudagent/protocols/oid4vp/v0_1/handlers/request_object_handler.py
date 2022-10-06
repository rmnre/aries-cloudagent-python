"""oid4vp auth request handler."""

import jwt
from typing import List, Optional

from marshmallow import ValidationError
from jwt.exceptions import DecodeError

from .....connections.models.conn_record import ConnRecord
from .....connections.models.connection_target import ConnectionTarget
from .....messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    HandlerException,
    RequestContext,
)
from .....messaging.decorators.attach_decorator import AttachDecorator
from .....messaging.models.base import BaseModelError
from .....messaging.responder import ResponderError
from .....indy.holder import IndyHolderError
from .....ledger.error import LedgerError
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
from ....present_proof.v2_0.models.pres_exchange import V20PresExRecord

from ..manager import OID4VPManager
from ..message_types import ARIES_PROTOCOL as OID4VP_PROTO
from ..messages.request_object import RequestObject as OID4VPRequestObject
from ..models.error_response import ErrorResponse
from ..models.oid4vp_record import OID4VPRecord
from ..models.request_object_data import RequestObjectData


class RequestObjectHandler(BaseHandler):
    """Handler class for oid4vp request object message."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """
        Handle oid4vp request object.

        Args:
            context: Request context
            responder: Responder callback
        """
        self._logger.debug("RequestObjectHandler called with context %s", context)
        assert isinstance(context.message, OID4VPRequestObject)
        profile = context.profile
        message = context.message
        request_obj = message.value
        self._logger.debug(
            "RequestObjectHandler received request object: %s", request_obj
        )

        # correlate request_obj with invitation via invitation_msg_id
        invitation_msg_id = message.invitation_msg_id
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
            tag_filter_oid = {"connection_id": conn_record.connection_id}
            oid4vp_record = await OID4VPRecord.retrieve_by_tag_filter(
                session, tag_filter_oid
            )
        if not oid4vp_record:
            raise HandlerException(
                "No OID4VP record found for connection id "
                f"{conn_record.connection_id}"
            )

        try:
            header = jwt.get_unverified_header(request_obj)
            # TODO: support signed and encrypted JWTs
            if not header["alg"] == "none":
                raise HandlerException(
                    "Signed and/or encrypted JWTs are currently not supported"
                )
            payload = jwt.decode(request_obj, options={"verify_signature": False})
            req_obj_data: RequestObjectData = RequestObjectData.deserialize(payload)
        except (
            DecodeError,
            BaseModelError,
            ValidationError,
        ):
            raise HandlerException("Not a valid auth request")

        self._logger.info("Received OID4VP request %s", req_obj_data.serialize())

        err_response = RequestObjectHandler._validate_request(req_obj_data)
        if err_response:
            oid4vp_record.state = OID4VPRecord.STATE_DONE
            conn_record.state = ConnRecord.State.ABANDONED.rfc23
            async with profile.session() as session:
                await oid4vp_record.save(session)
                await conn_record.save(session, reason="connection abandoned")
            target = ConnectionTarget(endpoint=req_obj_data.redirect_uri)
            await responder.send_reply(
                err_response.to_json(), target=target, protocol=OID4VP_PROTO
            )
            raise HandlerException(
                f"Received invalid auth request: {err_response.error}"
            )

        if not req_obj_data.presentation_definition:
            raise HandlerException(
                "presentation_definition parameter must be provided in auth request."
            )
        if req_obj_data.response_type.strip() != "vp_token":
            raise HandlerException("response_type must be 'vp_token'")
        if req_obj_data.response_mode != "post":
            raise HandlerException("Only response_mode 'post' is currently supported.")

        conn_record.state = ConnRecord.State.COMPLETED.rfc23
        async with profile.session() as session:
            await conn_record.save(session, reason="Set connection state to completed")

        # TODO: get presentation_definition_url if present
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
                            "challenge": req_obj_data.nonce,
                            "domain": req_obj_data.client_id,
                        },
                        "presentation_definition": req_obj_data.presentation_definition,
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
            oid4vp_id=oid4vp_record.oid4vp_id,
        )

        oid4vp_record.client_id = req_obj_data.client_id
        oid4vp_record.redirect_uri = req_obj_data.redirect_uri
        oid4vp_record.response_type = req_obj_data.response_type
        oid4vp_record.response_mode = req_obj_data.response_mode
        oid4vp_record.nonce = req_obj_data.nonce
        oid4vp_record.presentation_definition_url = (
            req_obj_data.presentation_definition_uri
        )
        oid4vp_record.pres_ex_id = pres_ex_record.pres_ex_id
        oid4vp_record.state = OID4VPRecord.STATE_REQUEST_RECEIVED
        async with profile.session() as session:
            await oid4vp_record.save(session, reason="received request object")

        pres_mgr = V20PresManager(profile)
        try:
            await pres_mgr.receive_pres_request(pres_ex_record)
        except V20PresManagerError as e:
            self._logger.exception("Error receiving auth request")
            raise HandlerException(e.roll_up)

        # If auto_present is enabled, respond immediately with presentation
        if pres_ex_record.auto_present:
            pres_message = None
            try:
                (pres_ex_record, pres_message) = await pres_mgr.create_pres(
                    pres_ex_record=pres_ex_record,
                    comment=(
                        f"auto-presented for proof requests"
                        f", pres_ex_record: {pres_ex_record.pres_ex_id}"
                    ),
                )
                oid4vp_mgr = OID4VPManager(profile)
                auth_response = await oid4vp_mgr.create_response(
                    oid4vp_record, pres_message
                )
                # transform response to string so responder does not add
                # DIDComm parameters via Schema.dump
                reply = auth_response.to_json()
                target = ConnectionTarget(endpoint=req_obj_data.redirect_uri)
                await responder.send_reply(reply, target=target, protocol=OID4VP_PROTO)
            except (
                BaseModelError,
                IndyHolderError,
                LedgerError,
                StorageError,
                StorageNotFoundError,
                WalletNotFoundError,
                V20PresFormatHandlerError,
                ResponderError,
            ) as err:
                self._logger.exception(err)
                if pres_ex_record:
                    async with profile.session() as session:
                        await pres_ex_record.save_error_state(
                            session,
                            reason=err.roll_up,
                        )

    @staticmethod
    def _validate_request(
        request: RequestObjectData, *, supported_scopes: List[str] = None
    ) -> Optional[ErrorResponse]:
        """
        Validate Auth Request.

        Args:
            request: The request to validate

        Returns:
            ErrorResponse if validation fails, else None

        """
        mutually_exclusive = (
            "presentation_definition",
            "presentation_definition_uri",
            "scope",
        )
        if (
            sum([bool(getattr(request, param, None)) for param in mutually_exclusive])
            != 1
        ):
            return ErrorResponse(ErrorResponse.ERROR_INVALID_REQUEST)

        if request.scope and request.scope not in (supported_scopes or []):
            return ErrorResponse(ErrorResponse.ERROR_INVALID_SCOPE)
