"""Classes to manage oid4vp connections."""

import json
import logging

from ....connections.base_manager import BaseConnectionManager
from ....connections.models.conn_record import ConnRecord
from ....connections.models.connection_target import ConnectionTarget
from ....core.error import BaseError
from ....core.profile import Profile
from ....messaging.responder import BaseResponder

from ...oid4vp.v0_1.models.auth_response import AuthResponse as OID4VPAuthResponse
from ...out_of_band.v1_0.messages.invitation import (
    InvitationMessage as OOBInvitationMessage,
)
from ...out_of_band.v1_0.messages.service import Service as OOBService
from ...present_proof.dif.pres_exch import (
    InputDescriptorMapping,
    PresentationSubmission,
)
from ...present_proof.v2_0.messages.pres_format import V20PresFormat
from ...present_proof.v2_0.models.pres_exchange import V20Pres

from .message_types import ARIES_PROTOCOL as OID4VP_PROTO
from .models.oid4vp_record import OID4VPRecord


class OID4VPManagerError(BaseError):
    """Connection error."""


class OID4VPManager(BaseConnectionManager):
    """Class for managing oid4vp connections."""

    def __init__(self, profile: Profile):
        """
        Initialize a OID4VPManager.

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
        request_uri = self.get_endpoint_from_invitation(invitation)
        if not request_uri:
            raise OID4VPManagerError(
                (
                    "Could not find an endpoint of type 'oid_request_uri' "
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
            connection_protocol=OID4VP_PROTO,
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

            # Save invitation for later processing
            await conn_rec.attach_invitation(session, invitation)

        if conn_rec.accept == ConnRecord.ACCEPT_AUTO:
            # TODO: support OOB connectionless requests feature?
            responder = self.profile.inject_or(BaseResponder)
            reply = json.dumps({"invitation_msg_id": conn_rec.invitation_msg_id})
            if responder:
                conn_rec.state = ConnRecord.State.REQUEST.rfc23
                async with self.profile.session() as session:
                    await conn_rec.save(session, reason="Fetching request_uri")

                await responder.send_reply(
                    reply,
                    connection_id=conn_rec.connection_id,
                    target=ConnectionTarget(endpoint=request_uri),
                    protocol=OID4VP_PROTO,
                )
            else:
                raise OID4VPManagerError(
                    "No responder available. Could not send response."
                )
        else:
            self._logger.debug("Connection invitation will await acceptance")

        return conn_rec

    @staticmethod
    def get_endpoint_from_invitation(invitation: OOBInvitationMessage) -> str:
        """
        Look up oid request_uri in OOB invitation.

        Args:
            invitation: an out-of-band invitation
        """
        for s in invitation.services or []:
            if isinstance(s, OOBService):
                if s.service_endpoint and s._type == "oid_request_uri":
                    return s.service_endpoint

        return None

    async def create_request(
        self,
        connection: ConnRecord,
        my_label: str = None,
        my_endpoint: str = None,
        mediation_id: str = None,
    ) -> str:
        """
        Create a new connection request for a previously-received invitation.

        Args:
            connection: The `ConnRecord` representing the invitation to accept
            my_label: My label
            my_endpoint: My endpoint

        Returns:
            The message payload to use in establishing the connection

        """
        async with self.profile.session() as session:
            invitation = await connection.retrieve_invitation(session)

        request_uri = OID4VPManager.get_endpoint_from_invitation(invitation)
        oid4vp_record = OID4VPRecord(
            state=OID4VPRecord.STATE_INITIAL,
            connection_id=connection.connection_id,
            request_uri=request_uri,
        )
        msg = json.dumps({"invitation_msg_id": connection.invitation_msg_id})
        # Update connection state
        connection.state = ConnRecord.State.REQUEST.rfc23
        async with self.profile.session() as session:
            await oid4vp_record.save(session)
            await connection.save(session, reason="Fetching request_uri")

        return msg

    async def create_response(
        self, oid4vp_record: OID4VPRecord, pres: V20Pres
    ) -> OID4VPAuthResponse:
        """
        Create an auth response message.

        Args:
            pres: Aries message containing verifiable presentation(s)
        """
        # TODO: support indy format
        dif_pres = pres.attachment(V20PresFormat.Format.DIF)
        pres_submission: PresentationSubmission = PresentationSubmission.deserialize(
            dif_pres["presentation_submission"]
        )
        descriptor_maps = pres_submission.descriptor_maps
        for index, descriptor_mapping in enumerate(descriptor_maps):
            descriptor_maps[index] = InputDescriptorMapping(
                id=descriptor_mapping.id,
                fmt="ldp_vp",
                path="$",
                path_nested=descriptor_mapping,
            )
        response = OID4VPAuthResponse(
            vp_token=dif_pres, presentation_submission=pres_submission
        )
        self._logger.debug("Created OID4VP auth response %s", response.serialize())
        oid4vp_record.state = OID4VPRecord.STATE_DONE
        async with self._profile.session() as session:
            await oid4vp_record.save(session, reason="set state to 'done'")
        return response
