import os

# Unit tests never reach for a model unless they stub one in explicitly.
os.environ.setdefault("GUARDYN_LLM", "off")
