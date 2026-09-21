import os

# Unit tests never reach for a model unless they stub one in explicitly.
os.environ.setdefault("ISNAD_LLM", "off")
