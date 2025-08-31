from typing import Dict, Any, List
from jsonschema import validate
from jsonschema.exceptions import ValidationError
from dateutil import parser as dtparser

_EVENT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "events": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "timestamp": {"type": "string"},
                    "event_type": {"type": "string"},
                    "src_ip": {"type": ["string", "null"]},
                    "dest_ip": {"type": ["string", "null"]},
                    "user": {"type": ["string", "null"]},
                    "domain": {"type": ["string", "null"]},
                    "url": {"type": ["string", "null"]},
                    "file_hash": {"type": ["string", "null"]},
                    "message": {"type": ["string", "null"]}
                },
                "required": ["timestamp", "event_type"],
                "additionalProperties": True
            }
        }
    },
    "required": ["events"],
    "additionalProperties": False
}

def _iso(dt_str: str) -> str:
    try:
        dt = dtparser.parse(dt_str)
        return dt.isoformat()
    except Exception:
        return dt_str

def validate_and_normalize(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Payload must be a JSON object.")
    try:
        validate(instance=payload, schema=_EVENT_SCHEMA)
    except ValidationError as e:
        raise ValueError(f"Schema validation failed: {str(e)}")

    normalized: List[Dict[str, Any]] = []
    keys = ["timestamp", "event_type", "src_ip", "dest_ip", "user", "domain", "url", "file_hash", "message"]
    for ev in payload["events"]:
        norm = {k: ev.get(k) for k in keys}
        if isinstance(norm["timestamp"], str):
            norm["timestamp"] = _iso(norm["timestamp"])
        normalized.append(norm)
    return {"events": normalized}
