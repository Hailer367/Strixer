from typing import Any
from strix.agents.base_agent import BaseAgent
from strix.llm.config import LLMConfig

class StrixDBAgent(BaseAgent):
    """
    StrixDB Agent - Permanent specialized sub-agent for knowledge management.
    It has exclusive control over StrixDB and monitors other agents to store
    and retrieve relevant information.
    """
    max_iterations = 1000 # Higher iteration limit as it stays alive

    def __init__(self, config: dict[str, Any]):
        # StrixDB Agent only needs specialized knowledge-related skills
        skills = ["strixdb_management"]

        # Override the default LLM config to ensure it has the right skills
        self.default_llm_config = LLMConfig(skills=skills)

        super().__init__(config)

    async def run(self, initial_task: str) -> dict[str, Any]:
        """
        Start the StrixDB Agent with an initial task.
        """
        return await self.agent_loop(task=initial_task)
