from strix.config import Config


class LLMConfig:
    def __init__(
        self,
        model_name: str | None = None,
        enable_prompt_caching: bool = True,
        skills: list[str] | None = None,
        timeout: int | None = None,
        scan_mode: str = "deep",
    ):
        self.model_name = model_name or Config.get("strix_llm")

        if not self.model_name:
            raise ValueError("STRIX_LLM environment variable must be set and not empty")

        # Auto-add openai/ prefix for Qwen models if missing (required for LiteLLM with custom endpoints)
        if self.model_name and "qwen" in self.model_name.lower() and "/" not in self.model_name:
            self.model_name = f"openai/{self.model_name}"

        self.enable_prompt_caching = enable_prompt_caching
        self.skills = skills or []

        self.timeout = timeout or int(Config.get("llm_timeout") or "300")

        self.scan_mode = scan_mode if scan_mode in ["quick", "standard", "deep"] else "deep"
