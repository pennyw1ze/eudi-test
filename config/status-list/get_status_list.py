# Status list retrieval endpoint.
#
# Based on the endpoints/get_status_list.py that ships in
# eudi-srv-pid-issuer/docker-compose, with the content negotiation fixed.
#
# Upstream compares the Accept header with exact string equality:
#
#     if accept == "application/statuslist+jwt":
#
# Real clients do not send exactly that. Keycloak's ABCA extension and the issuer both
# dereference these URIs with an ordinary Accept header carrying several media types
# and/or q-values, so the comparison fails and they get a 406 instead of the token.
# That made client authentication and key attestation fail with a generic
# "Authentication failed", several layers away from the actual cause.
#
# This matches on the media type appearing anywhere in the header, and treats a missing
# or wildcard Accept as a request for the JWT form.

import os

from flask import jsonify, request, send_file


def _wants(accept, media_type):
    return media_type in accept


@token.route("/<country>/<doctype>/<list>", methods=["GET"])
def get_status_list(country, doctype, list):
    accept = request.headers.get("Accept") or ""

    if _wants(accept, "application/statuslist+jwt"):
        filename, mimetype = "token_status_list.jwt", "application/statuslist+jwt"
    elif _wants(accept, "application/statuslist+cwt"):
        filename, mimetype = "token_status_list.cwt", "application/statuslist+cwt"
    elif accept.strip() == "" or "*/*" in accept:
        # No preference expressed; the JWT form is what every consumer here reads.
        filename, mimetype = "token_status_list.jwt", "application/statuslist+jwt"
    else:
        return jsonify({"error": "Not Acceptable"}), 406

    file_path = os.path.join(
        cfgservice.status_list_dir, "token_status_list", country, doctype, list, filename
    )

    if not os.path.isfile(file_path):
        return "", 404

    return send_file(file_path, mimetype=mimetype)
