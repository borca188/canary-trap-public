from flask import Blueprint, jsonify, request

from events import list_events_for_token
from routes.honeypot import callback_url_for, custom_url, reserved_path_segments
from security import add_frame_headers, guard_api
from tokens import (
    TokenCreationError,
    create_token,
    get_token,
    list_tokens,
    normalize_custom_path,
)

api_bp = Blueprint("api", __name__, url_prefix="/api")
api_bp.before_request(guard_api)
api_bp.after_request(add_frame_headers)


@api_bp.route("/tokens", methods=["POST"])
def create_token_route():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        # Missing, malformed or non-object JSON (e.g. a list or a bare string).
        return jsonify({"error": "request body must be a JSON object"}), 400
    document_ref = data.get("document_ref")

    if not document_ref or not isinstance(document_ref, str):
        return jsonify({"error": "document_ref (string) is required"}), 400

    raw_path = data.get("custom_path")
    if raw_path is not None and not isinstance(raw_path, str):
        return jsonify({"error": "custom_path must be a string"}), 400
    reserved = reserved_path_segments()
    try:
        token = create_token(document_ref, normalize_custom_path(raw_path, reserved), reserved)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except TokenCreationError as exc:
        return jsonify({"error": str(exc)}), 503

    token["callback_url"] = callback_url_for(token)
    if token["custom_path"]:
        token["custom_url"] = custom_url(token["custom_path"])
    return jsonify(token), 201


@api_bp.route("/tokens", methods=["GET"])
def list_tokens_route():
    tokens = list_tokens()
    for token in tokens:
        token["callback_url"] = callback_url_for(token)
        if token["custom_path"]:
            token["custom_url"] = custom_url(token["custom_path"])
    return jsonify(tokens)


@api_bp.route("/tokens/<token_id>/events", methods=["GET"])
def list_token_events_route(token_id):
    if get_token(token_id) is None:
        return jsonify({"error": "unknown token_id"}), 404

    include_archived = request.args.get("include_archived") in ("1", "true")
    return jsonify(list_events_for_token(token_id, include_archived=include_archived))
