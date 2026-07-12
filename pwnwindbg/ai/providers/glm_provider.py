"""Z.ai GLM provider (GLM Coding Plan subscription).

GLM's coding-plan API is OpenAI-compatible, so this reuses all of
:class:`OpenAISession`'s streaming/SSE machinery and only swaps the default
endpoint, model and config-section name.

The coding-plan (subscription) endpoint is distinct from the pay-as-you-go
one — it is ``https://api.z.ai/api/coding/paas/v4`` (OpenAI protocol). See
https://docs.z.ai/devpack/quick-start. Auth is ``Authorization: Bearer <key>``
with a ``<id>.<secret>`` key from the Z.AI Open Platform.
"""

from .openai_provider import OpenAISession


class GLMSession(OpenAISession):
    """Chat session against the Z.ai GLM Coding Plan OpenAI-compatible endpoint."""

    provider_name = "glm"
    default_base = "https://api.z.ai/api/coding/paas/v4"
    default_model = "glm-5.2"
