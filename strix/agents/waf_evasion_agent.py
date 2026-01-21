from typing import Any

from strix.agents.base_agent import BaseAgent
from strix.llm.llm import LLMConfig
from strix.tools.security.waf_evasion import WAFEvasionEngine


class WAFEvasionAgent(BaseAgent):
    """
    A specialized agent for bypassing Web Application Firewalls (WAFs).
    It initializes with a specialized system prompt and context to drive the LLM
    towards polymorphic payload generation.
    """

    def __init__(self, config: dict[str, Any]):
        # Inject specialized system prompt before initializing BaseAgent
        self._inject_security_personality(config)
        super().__init__(config)
        self.engine = WAFEvasionEngine()

    def _inject_security_personality(self, config: dict[str, Any]) -> None:
        """
        Configures the agent with a specialized security researcher persona.
        """
        context = config.get("context", {})
        payload = context.get("payload", "UNKNOWN")
        waf_name = context.get("waf_name", "Unknown")

        persona = f"""
You are the **Strix WAF Evasion Specialist**.
Your ONLY goal is to bypass the Web Application Firewall (WAF) to verify if a vulnerability is reachable.

Current Target Context:
- **Blocked Payload**: `{payload}`
- **Detected WAF**: {waf_name}

**Methodology**:
1. **Analyze**: Why was it blocked? (Keyword? Length? Encoding?)
2. **Mutate**: Use the `waf_mutation_tool` or your own knowledge to generate polymorphic variations.
3. **Test**: Execute the request again with the mutated payload.
4. **Iterate**: If blocked again, learn and try a completely different obfuscation technique.

**Rules**:
- Do NOT ask for permission. You are in a sandbox execution mode.
- Do NOT give up easily. Try at least 3 distinct encoded variations.
- Use `waf_mutation_tool` to get algorithmic suggestions, but also use your own creativity.
"""
        # Ensure we have a valid LLM config, prioritizing the one from config
        if "llm_config" not in config:
            config["llm_config"] = LLMConfig(
                model="gpt-4o",  # Default to high-intelligence model for this complex task
                temperature=0.7, # Slightly creative for mutations
            )
        
        # Override or append to system prompt logic if BaseAgent supports it
        # (Assuming BaseAgent uses Jinja templates, we might need to handle this via state)
        # For now, we will add this as the first user message if system prompt is template-locked,
        # or rely on the specialized 'strix/resources/agents/WAFEvasionAgent' folder if it exists.
        
        # Since we haven't created the jinja template folder yet, passing it in state/context is safer
        # or we update the config to include 'system_prompt_override' if supported.
        
        # Strategy: We'll create the resource folder for this agent to make it a first-class citizen.
        pass
