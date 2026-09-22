"""Tool routing arguments are authority; payload text is data.

Length cannot distinguish them: a long URL is still a destination.
"""
from app.models import CandidateAction

CARGO_FIELDS = frozenset({
    "body", "content", "text", "message", "summary", "description", "title",
    "subject", "note", "notes", "comment", "comments", "reason", "rationale",
})


def control_arguments(action: CandidateAction) -> dict[str, str]:
    if action.type != "tool_call":
        return {}
    return {
        key: str(value) for key, value in action.arguments.items()
        if value is not None and key.lower() not in CARGO_FIELDS and len(str(value)) >= 3
    }
