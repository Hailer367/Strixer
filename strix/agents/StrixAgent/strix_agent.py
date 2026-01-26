from typing import Any

from strix.agents.base_agent import BaseAgent
from strix.llm.config import LLMConfig


class StrixAgent(BaseAgent):
    max_iterations = 300

    def __init__(self, config: dict[str, Any]):
        default_skills = []

        state = config.get("state")
        if state is None or (hasattr(state, "parent_id") and state.parent_id is None):
            default_skills = ["root_agent"]

        self.default_llm_config = LLMConfig(skills=default_skills)

        super().__init__(config)

    async def execute_scan(self, scan_config: dict[str, Any]) -> dict[str, Any]:  # noqa: PLR0912
        # Automatically spawn permanent sub-agents at the start of every scan
        await self._spawn_strixdb_agent(scan_config)
        await self._spawn_exploit_agent(scan_config)

        user_instructions = scan_config.get("user_instructions", "")
        targets = scan_config.get("targets", [])

        repositories = []
        local_code = []
        urls = []
        ip_addresses = []

        for target in targets:
            target_type = target["type"]
            details = target["details"]
            workspace_subdir = details.get("workspace_subdir")
            workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else "/workspace"

            if target_type == "repository":
                repo_url = details["target_repo"]
                cloned_path = details.get("cloned_repo_path")
                repositories.append(
                    {
                        "url": repo_url,
                        "workspace_path": workspace_path if cloned_path else None,
                    }
                )

            elif target_type == "local_code":
                original_path = details.get("target_path", "unknown")
                local_code.append(
                    {
                        "path": original_path,
                        "workspace_path": workspace_path,
                    }
                )

            elif target_type == "web_application":
                urls.append(details["target_url"])
            elif target_type == "ip_address":
                ip_addresses.append(details["target_ip"])

        task_parts = []

        if repositories:
            task_parts.append("\n\nRepositories:")
            for repo in repositories:
                if repo["workspace_path"]:
                    task_parts.append(f"- {repo['url']} (available at: {repo['workspace_path']})")
                else:
                    task_parts.append(f"- {repo['url']}")

        if local_code:
            task_parts.append("\n\nLocal Codebases:")
            task_parts.extend(
                f"- {code['path']} (available at: {code['workspace_path']})" for code in local_code
            )

        if urls:
            task_parts.append("\n\nURLs:")
            task_parts.extend(f"- {url}" for url in urls)

        if ip_addresses:
            task_parts.append("\n\nIP Addresses:")
            task_parts.extend(f"- {ip}" for ip in ip_addresses)

        task_description = " ".join(task_parts)

        if user_instructions:
            task_description += f"\n\nSpecial instructions: {user_instructions}"

        return await self.agent_loop(task=task_description)

    async def _spawn_strixdb_agent(self, scan_config: dict[str, Any]) -> None:
        """Spawn the permanent StrixDB Agent."""
        from strix.agents.StrixDBAgent import StrixDBAgent
        from strix.agents.state import AgentState
        from strix.llm.config import LLMConfig
        import threading
        from strix.tools.agents_graph.agents_graph_actions import _run_agent_in_thread, _agent_instances, _running_agents

        # Determine target display name
        targets = scan_config.get("targets", [])
        target_names = []
        for t in targets:
            if t["type"] == "web_application":
                target_names.append(t["details"].get("target_url", ""))
            elif t["type"] == "repository":
                target_names.append(t["details"].get("target_repo", ""))
            elif t["type"] == "ip_address":
                target_names.append(t["details"].get("target_ip", ""))
            elif t["type"] == "local_code":
                target_names.append(t["details"].get("target_path", ""))

        target_display = ", ".join(target_names) or "Unknown Target"

        initial_task = (
            f"You are the StrixDB Agent for the current scan of {target_display}. "
            "Initialize target tracking, provide a detailed briefing to the Root Agent, "
            "and monitor all agents to ensure all valuable knowledge is captured in StrixDB. "
            "Guide agents when necessary with relevant payloads and history from StrixDB."
        )

        state = AgentState(
            task=initial_task,
            agent_name="StrixDB Agent",
            parent_id=self.state.agent_id,
            max_iterations=1000
        )

        llm_config = LLMConfig(skills=["strixdb_management"])

        agent_config = {
            "llm_config": llm_config,
            "state": state,
            "non_interactive": self.non_interactive
        }

        db_agent = StrixDBAgent(agent_config)
        _agent_instances[state.agent_id] = db_agent

        thread = threading.Thread(
            target=_run_agent_in_thread,
            args=(db_agent, state, []),
            daemon=True,
            name=f"Agent-StrixDBAgent-{state.agent_id}",
        )
        thread.start()
        _running_agents[state.agent_id] = thread

    async def _spawn_exploit_agent(self, scan_config: dict[str, Any]) -> None:
        """Spawn the permanent Exploit Agent."""
        from strix.agents.ExploitAgent import ExploitAgent
        from strix.agents.state import AgentState
        from strix.llm.config import LLMConfig
        import threading
        from strix.tools.agents_graph.agents_graph_actions import _run_agent_in_thread, _agent_instances, _running_agents

        # Determine target display name
        targets = scan_config.get("targets", [])
        target_names = []
        for t in targets:
            if t["type"] == "web_application":
                target_names.append(t["details"].get("target_url", ""))
            elif t["type"] == "repository":
                target_names.append(t["details"].get("target_repo", ""))
            elif t["type"] == "ip_address":
                target_names.append(t["details"].get("target_ip", ""))
            elif t["type"] == "local_code":
                target_names.append(t["details"].get("target_path", ""))

        target_display = ", ".join(target_names) or "Unknown Target"

        initial_task = (
            f"You are the Exploit Agent for the current scan of {target_display}. "
            "Your primary mission is to find, craft, and execute exploits against all discovered services and applications. "
            "Wait for the initial briefing from the StrixDB Agent. If none is provided, start your own reconnaissance. "
            "Provide the Root Agent with working exploits and detailed execution commands when requested or when you find something significant."
        )

        state = AgentState(
            task=initial_task,
            agent_name="Exploit Agent",
            parent_id=self.state.agent_id,
            max_iterations=500
        )

        llm_config = LLMConfig(skills=["exploit_master", "web_exploitation", "network_exploitation", "bypasses"])

        agent_config = {
            "llm_config": llm_config,
            "state": state,
            "non_interactive": self.non_interactive
        }

        exploit_agent = ExploitAgent(agent_config)
        _agent_instances[state.agent_id] = exploit_agent

        thread = threading.Thread(
            target=_run_agent_in_thread,
            args=(exploit_agent, state, []),
            daemon=True,
            name=f"Agent-ExploitAgent-{state.agent_id}",
        )
        thread.start()
        _running_agents[state.agent_id] = thread
