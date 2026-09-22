"""All observed content, including an observation sent outside history."""
from app.models import ConversationItem, DefenseRequest


def observed_items(request: DefenseRequest):
    yield from request.conversation
    observation = request.observation
    if observation is not None and not any(
        item.content == observation.content and item.provenance_ids == observation.provenance_ids
        for item in request.conversation
    ):
        yield ConversationItem(role="tool", kind=observation.kind, content=observation.content,
                               provenance_ids=observation.provenance_ids)
