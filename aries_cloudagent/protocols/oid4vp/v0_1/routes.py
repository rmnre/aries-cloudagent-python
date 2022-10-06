"""Admin routes for oid4vp record management."""

from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    querystring_schema,
    response_schema,
)
from marshmallow import fields, validate, ValidationError

from ....admin.request_context import AdminRequestContext
from ....messaging.models.base import BaseModelError
from ....messaging.models.openapi import OpenAPISchema
from ....messaging.valid import UUIDFour, UUID4
from ....storage.error import StorageError, StorageNotFoundError
from ....storage.base import BaseStorage

from .message_types import SPEC_URI
from .models.oid4vp_record import OID4VPRecord, OID4VPRecordSchema


class OID4VPModuleResponseSchema(OpenAPISchema):
    """Response schema for OID4VP Module."""


class OID4VPRecordListQueryStringSchema(OpenAPISchema):
    """Parameters and validators for presentation exchange list query."""

    connection_id = fields.UUID(
        description="Connection identifier",
        required=False,
        example=UUIDFour.EXAMPLE,  # typically but not necessarily a UUID4
    )
    pres_ex_id = fields.UUID(
        description="Presentation Exchange Record V2.0 identifier",
        required=False,
        example=UUIDFour.EXAMPLE,  # typically but not necessarily a UUID4
    )
    state = fields.Str(
        description="oid4vp state",
        required=False,
        validate=validate.OneOf(
            [
                getattr(OID4VPRecord, m)
                for m in vars(OID4VPRecord)
                if m.startswith("STATE_")
            ]
        ),
    )


class OID4VPRecordListSchema(OpenAPISchema):
    """Result schema for an oid4vp record query."""

    results = fields.List(
        fields.Nested(OID4VPRecordSchema()),
        description="OID4VP records",
    )


class OID4VPIdMatchInfoSchema(OpenAPISchema):
    """Path parameters for request taking oid4vp id."""

    oid4vp_id = fields.Str(
        description="oid4vp record identifier", required=True, **UUID4
    )


@docs(tags=["oid4vp v0.1"], summary="Fetch all oid4vp records")
@querystring_schema(OID4VPRecordListQueryStringSchema)
@response_schema(OID4VPRecordListSchema(), 200, description="")
async def oid4vp_list(request: web.BaseRequest):
    """
    Request handler for searching oid4vp records.

    Args:
        request: aiohttp request object

    Returns:
        The oid4vp record list response

    """
    context: AdminRequestContext = request["context"]
    profile = context.profile

    tag_filter = {
        k: request.query[k]
        for k in ("connection_id", "pres_ex_id")
        if request.query.get(k, "") != ""
    }
    post_filter = (
        {"state": request.query["state"]}
        if request.query.get("state", "") != ""
        else {}
    )

    try:
        async with profile.session() as session:
            records = await OID4VPRecord.query(
                session=session,
                tag_filter=tag_filter,
                post_filter_positive=post_filter,
            )
        results = [record.serialize() for record in records]
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"results": results})


@docs(
    tags=["oid4vp v0.1"],
    summary="Fetch a single oid4vp record",
)
@match_info_schema(OID4VPIdMatchInfoSchema())
@response_schema(OID4VPRecordSchema(), 200, description="")
async def oid4vp_record_retrieve(request: web.BaseRequest):
    """
    Request handler for fetching a single oid4vp record.

    Args:
        request: aiohttp request object

    Returns:
        The oid4vp record response

    """
    context: AdminRequestContext = request["context"]
    profile = context.profile

    oid4vp_id = request.match_info["oid4vp_id"]
    oid4vp_record = None
    try:
        async with profile.session() as session:
            oid4vp_record = await OID4VPRecord.retrieve_by_id(session, oid4vp_id)
        result = oid4vp_record.serialize()
    except StorageNotFoundError as err:
        # no such pres ex record: not protocol error, user fat-fingered id
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (BaseModelError, StorageError) as err:
        # present but broken or hopeless: protocol error
        if oid4vp_record:
            async with profile.session() as session:
                await oid4vp_record.save_error_state(session, reason=err.roll_up)

    return web.json_response(result)


@docs(
    tags=["oid4vp v0.1"],
    summary="Remove an existing oid4vp record",
)
@match_info_schema(OID4VPIdMatchInfoSchema())
@response_schema(OID4VPModuleResponseSchema(), description="")
async def oid4vp_record_remove(request: web.BaseRequest):
    """
    Request handler for removing an oid4vp record.

    Args:
        request: aiohttp request object

    """
    context: AdminRequestContext = request["context"]

    oid4vp_id = request.match_info["oid4vp_id"]
    oid4vp_record = None
    try:
        async with context.profile.session() as session:
            try:
                oid4vp_record = await OID4VPRecord.retrieve_by_id(session, oid4vp_id)
                await oid4vp_record.delete_record(session)
            except (BaseModelError, ValidationError):
                storage = session.inject(BaseStorage)
                storage_record = await storage.get_record(
                    record_type=OID4VPRecord.RECORD_TYPE, record_id=oid4vp_id
                )
                await storage.delete_record(storage_record)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except StorageError as err:
        raise web.HTTPBadRequest(reason=err.roll_up)

    return web.json_response({})


async def register(app: web.Application):
    """Register routes."""

    app.add_routes(
        [
            web.get(
                "/oid4vp/records",
                oid4vp_list,
                allow_head=False,
            ),
            web.get(
                "/oid4vp/records/{oid4vp_id}",
                oid4vp_record_retrieve,
                allow_head=False,
            ),
            web.delete(
                "/oid4vp/records/{oid4vp_id}",
                oid4vp_record_remove,
            ),
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "oid4vp v0.1",
            "description": "OID4VP v0.1",
            "externalDocs": {"description": "Specification", "url": SPEC_URI},
        }
    )
