"""Classes to manage px-over-http connections."""

import json
import logging

from ....connections.base_manager import BaseConnectionManager
from ....connections.models.conn_record import ConnRecord
from ....connections.models.connection_target import ConnectionTarget
from ....core.error import BaseError
from ....core.profile import Profile
from ....messaging.decorators.attach_decorator import AttachDecoratorDataJWS
from ....messaging.responder import BaseResponder
from ....storage.error import StorageNotFoundError

from ...out_of_band.v1_0.messages.invitation import (
    InvitationMessage as OOBInvitationMessage,
)
from ...out_of_band.v1_0.messages.service import Service as OOBService
from ...present_proof.v2_0.messages.pres import V20Pres
from ...present_proof.v2_0.models.pres_exchange import V20PresExRecord

from .message_types import ARIES_PROTOCOL as PXHTTP_PROTO
from .messages.ack import Ack
from .messages.auth_response import AuthResponse
from .messages.invitation_response import InvitationResponse


class PXHTTPManagerError(BaseError):
    """Connection error."""


class PXHTTPManager(BaseConnectionManager):
    """Class for managing px-over-http connections."""

    def __init__(self, profile: Profile):
        """
        Initialize a PXHTTPManager.

        Args:
            profile: The profile for this manager
        """
        self._profile = profile
        self._logger = logging.getLogger(__name__)
        super().__init__(self._profile)

    @property
    def profile(self) -> Profile:
        """
        Accessor for the current profile.

        Returns:
            The profile for this manager

        """
        return self._profile

    async def create_invitation_response(
        self,
        conn_rec: ConnRecord,
        my_label: str = None,
        mediation_id: str = None,
    ) -> InvitationResponse:
        """
        Create a new invitation response for a previously-received invitation.

        Args:
            conn_rec: The `ConnRecord` representing the invitation to accept
            my_label: My label for response
            mediation_id: The record id for mediation that contains routing_keys and
                service endpoint

        Returns:
            A new `InvitationResponse` message to send to the inviter

        """
        # # Mediation Support
        # mediation_mgr = MediationManager(self.profile)
        # keylist_updates = None
        # mediation_record = await mediation_record_if_id(
        #     self.profile,
        #     mediation_id,
        #     or_default=True,
        # )
        # base_mediation_record = None

        # # Multitenancy setup
        # multitenant_mgr = self.profile.inject_or(BaseMultitenantManager)
        # wallet_id = self.profile.settings.get("wallet.id")
        # if multitenant_mgr and wallet_id:
        #     base_mediation_record = await multitenant_mgr.get_default_mediator()

        # my_info = None

        # if conn_rec.my_did:
        #     async with self.profile.session() as session:
        #         wallet = session.inject(BaseWallet)
        #         my_info = await wallet.get_local_did(conn_rec.my_did)
        # else:
        #     # Create new DID for connection
        #     async with self.profile.session() as session:
        #         wallet = session.inject(BaseWallet)
        #         my_info = await wallet.create_local_did(
        #             method=DIDMethod.SOV,
        #             key_type=KeyType.ED25519,
        #         )
        #     conn_rec.my_did = my_info.did
        #     keylist_updates = await mediation_mgr.add_key(
        #         my_info.verkey, keylist_updates
        #     )
        #     # Add mapping for multitenant relay
        #     if multitenant_mgr and wallet_id:
        #         await multitenant_mgr.add_key(wallet_id, my_info.verkey)

        # # Create invitation response message
        # if my_endpoint:
        #     my_endpoints = [my_endpoint]
        # else:
        #     my_endpoints = []
        #     default_endpoint = self.profile.settings.get("default_endpoint")
        #     if default_endpoint:
        #         my_endpoints.append(default_endpoint)
        #     my_endpoints.extend(self.profile.settings.get("additional_endpoints", []))
        # did_doc = await self.create_did_document(
        #     my_info,
        #     conn_rec.inbound_connection_id,
        #     my_endpoints,
        #     mediation_records=list(
        #         filter(None, [base_mediation_record, mediation_record])
        #     ),
        # )
        # if (
        #     conn_rec.their_public_did is not None
        #     and conn_rec.their_public_did.startswith("did:")
        # ):
        #     qualified_did = conn_rec.their_public_did
        # else:
        #     qualified_did = f"did:sov:{conn_rec.their_public_did}"
        # pthid = conn_rec.invitation_msg_id or qualified_did
        pthid = conn_rec.invitation_msg_id
        # attach = AttachDecorator.data_base64(did_doc.serialize())
        # async with self.profile.session() as session:
        #     wallet = session.inject(BaseWallet)
        #     await attach.data.sign(my_info.verkey, wallet)
        if not my_label:
            my_label = self.profile.settings.get("default_label")
        invitation_response = InvitationResponse(
            invitation_msg_id=conn_rec.invitation_msg_id
        )
        invitation_response.assign_thread_id(thid=invitation_response._id, pthid=pthid)

        # Update connection state
        conn_rec.request_id = invitation_response._id
        conn_rec.state = ConnRecord.State.REQUEST.rfc23
        async with self.profile.session() as session:
            await conn_rec.save(session, reason="Created invitation response")

        # # Notify Mediator
        # if keylist_updates and mediation_record:
        #     responder = self.profile.inject_or(BaseResponder)
        #     await responder.send(
        #         keylist_updates, connection_id=mediation_record.connection_id
        #     )
        return invitation_response

    async def receive_invitation(
        self,
        invitation: OOBInvitationMessage,
        their_public_did: str = None,
        auto_accept: bool = None,
        alias: str = None,
        mediation_id: str = None,
    ) -> ConnRecord:
        """
        Create a new connection record to track a received invitation.

        Args:
            invitation: invitation to store
            their_public_did: their public DID
            auto_accept: set to auto-accept invitation (None to use config)
            alias: optional alias to set on record
            mediation_id: record id for mediation with routing_keys, service endpoint

        Returns:
            The new `ConnRecord` instance

        """
        # TODO: Support fetching px-over-http endpoint from DIDDoc of public DID
        pxhttp_endpoint = self.get_endpoint_from_invitation(invitation)
        if not pxhttp_endpoint:
            raise PXHTTPManagerError(
                (
                    "Could not find an endpoint of type 'px-over-http' "
                    "in invitation message."
                )
            )

        accept = (
            ConnRecord.ACCEPT_AUTO
            if (
                auto_accept
                or (
                    auto_accept is None
                    and self.profile.settings.get("debug.auto_accept_invites")
                )
            )
            else ConnRecord.ACCEPT_MANUAL
        )

        # Create connection record
        conn_rec = ConnRecord(
            invitation_msg_id=invitation._id,
            their_label=invitation.label,
            their_role=ConnRecord.Role.RESPONDER.rfc23,
            state=ConnRecord.State.INVITATION.rfc23,
            accept=accept,
            alias=alias,
            their_public_did=their_public_did,
            connection_protocol=PXHTTP_PROTO,
        )

        async with self.profile.session() as session:
            await conn_rec.save(
                session,
                reason="Created new connection record from invitation",
                log_params={
                    "invitation": invitation,
                    "their_role": ConnRecord.Role.RESPONDER.rfc23,
                },
            )

            # Save the invitation for later processing
            await conn_rec.attach_invitation(session, invitation)

        if conn_rec.accept == ConnRecord.ACCEPT_AUTO:
            invitation_response = await self.create_invitation_response(
                conn_rec, mediation_id=mediation_id
            )
            # transform request to string so responder does not add
            # DIDComm parameters via Schema.dump
            reply = json.dumps(
                {"invitation_msg_id": invitation_response.invitation_msg_id}
            )
            responder = self.profile.inject_or(BaseResponder)
            if responder:
                # conn_rec.state = ConnRecord.State.REQUEST.rfc23
                # async with self.profile.session() as session:
                #     await conn_rec.save(session, reason="Sending connection request")

                await responder.send_reply(
                    reply,
                    connection_id=conn_rec.connection_id,
                    target=ConnectionTarget(endpoint=pxhttp_endpoint),
                    protocol=PXHTTP_PROTO,
                )
            else:
                raise PXHTTPManagerError(
                    "No responder available. Could not send response."
                )
        else:
            self._logger.debug("Connection invitation will await acceptance")

        return conn_rec

    def create_response(
        self,
        pres: V20Pres,
        session: str,
    ) -> AuthResponse:
        """
        Create an auth response message.

        Args:
            pres: Aries message containing verifiable presentation(s)
            session: px-over-http session identifier
        """
        payload = pres.presentations_attach[0].data.base64
        jws: AttachDecoratorDataJWS = pres.presentations_attach[0].data.jws
        response = AuthResponse(
            id_token=f"{jws.protected}.{payload}.{jws.signature}",
            session=session,
        )
        return response

    @staticmethod
    def get_endpoint_from_invitation(invitation: OOBInvitationMessage) -> str:
        """
        Look up px-over-http endpoint in OOB invitation.

        Args:
            invitation: an out-of-band invitation
        """
        for s in invitation.services or []:
            if isinstance(s, OOBService):
                if s.service_endpoint and s._type == "px-over-http":
                    return s.service_endpoint

        return None

    async def receive_ack(self, message: Ack):
        """
        Receive an ack message.

        Returns:
            presentation exchange record, retrieved and updated

        """
        self._logger.info("PXHTTPManager: ACK received")
        tag_filter = None
        post_filter = {
            "pxhttp_session": message.session,
            "state": V20PresExRecord.STATE_PRESENTATION_SENT,
            "role": V20PresExRecord.ROLE_PROVER,
        }
        try:
            async with self.profile.session() as session:
                pres_ex_record = await V20PresExRecord.retrieve_by_tag_filter(
                    session, tag_filter, post_filter
                )
                conn_record = await ConnRecord.retrieve_by_id(
                    session, pres_ex_record.connection_id
                )

                if message.status == "OK":
                    pres_ex_record.state = V20PresExRecord.STATE_DONE
                    await pres_ex_record.save(session)
                    # auto remove connection record
                    self._logger.info(
                        "PXHTTPManager: deleting connection record '%s' after "
                        "successful transmission of auth response",
                        conn_record.connection_id,
                    )
                    await conn_record.delete_record(session)
                else:
                    self._logger.error(
                        "Receiver indicated a problem during auth response transmission."
                    )
        except StorageNotFoundError as err:
            raise PXHTTPManagerError(
                "Corresponding records for ack message not found."
            ) from err
