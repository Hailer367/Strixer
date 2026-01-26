from typing import Any
from strix.tools.registry import register_tool

@register_tool(sandbox_execution=False)
def view_all_agents_activity(agent_state: Any) -> dict[str, Any]:
    """
    View the activity (messages and tool outputs) of all agents.
    ONLY the StrixDB Agent is allowed to use this tool for monitoring purposes.

    Args:
        agent_state: The current agent state (automatically passed).

    Returns:
        dict with: success, agents_activity (list of agents with their tasks and recent messages/tools)
    """
    agent_name = getattr(agent_state, "agent_name", "")
    if agent_name != "StrixDB Agent":
        return {
            "success": False,
            "error": "Access Denied. Only the StrixDB Agent can use this monitoring tool."
        }

    try:
        from strix.tools.agents_graph.agents_graph_actions import _agent_graph, _agent_messages, _agent_states

        activity = []
        for agent_id, node in _agent_graph.get("nodes", {}).items():
            if agent_id == agent_state.agent_id:
                continue

            agent_activity = {
                "agent_id": agent_id,
                "name": node.get("name"),
                "task": node.get("task"),
                "status": node.get("status"),
                "recent_messages": [],
                "recent_actions": []
            }

            # Get messages from the agent state if available
            state = _agent_states.get(agent_id)
            if state:
                # Last 5 messages for context
                agent_activity["recent_messages"] = state.messages[-5:]
                agent_activity["recent_actions"] = state.actions_taken[-5:]

            activity.append(agent_activity)

        return {
            "success": True,
            "agents_activity": activity
        }

    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to retrieve agents activity: {str(e)}"
        }
