export enum AgentStatus {
  IDLE = 'IDLE',
  RUNNING = 'RUNNING',
  COMPLETED = 'COMPLETED',
  ERROR = 'ERROR',
  PAUSED = 'PAUSED'
}

export interface AgentNode {
  id: string;
  name: string;
  type: 'orchestrator' | 'scanner' | 'fuzzer' | 'exploiter' | 'reporter' | string;
  status: AgentStatus | string;
  children?: AgentNode[];
  task?: string;
  current_task?: string;
  parent_id?: string | null;
  tool_count?: number;
}

export interface ReasoningLog {
  id: string;
  timestamp: string;
  thought: string;
  tool?: string;
  toolInput?: string;
  toolOutput?: string;
  action: string;
  target?: string;
  severity?: 'info' | 'low' | 'medium' | 'high' | 'critical';
}

export interface DashboardStats {
  apiCallsTotal: number;
  apiCallsMinute: number;
  timeRemaining: number;
  vulnerabilitiesFound: number;
  activeAgents: number;
  tokensUsed?: number;
  costUsd?: number;
  toolsExecuted?: number;
}

// Strix API State Types
export interface ScanConfig {
  target: string;
  timeframe: number;
  scan_mode: string;
  model: string;
  prompt: string;
}

export interface TimeInfo {
  start_time: string;
  duration_minutes: number;
  elapsed_minutes: number;
  remaining_minutes: number;
  progress_percentage: number;
  phase: string;
  is_warning: boolean;
  is_critical: boolean;
}

export interface AgentInfo {
  id: string;
  name: string;
  type: string;
  parent_id: string | null;
  status: string;
  current_task: string;
  tool_count: number;
}

export interface Vulnerability {
  id: string;
  severity: string;
  title: string;
  description: string;
  endpoint: string;
  evidence: string;
  timestamp: string;
}

export interface ToolExecution {
  id: string;
  tool: string;
  input: string;
  output: string;
  status: string;
  duration_ms: number;
  timestamp: string;
}

export interface Stats {
  api_calls: number;
  tokens_used: number;
  cost_usd: number;
  tools_executed: number;
  vulnerabilities_found: number;
  active_agents: number;
}

export interface LiveFeedEntry {
  id?: string;
  type?: string;
  message?: string;
  tool?: string;
  input?: string;
  output?: string;
  severity?: string;
  timestamp: string;
}

export interface StrixState {
  scan_config: ScanConfig;
  time: TimeInfo;
  agents: AgentInfo[];
  vulnerabilities: Vulnerability[];
  tool_executions: ToolExecution[];
  stats: Stats;
  live_feed: LiveFeedEntry[];
  last_updated: string;
}

// Helper function to convert AgentInfo array to tree structure
export function buildAgentTree(agents: AgentInfo[]): AgentNode | null {
  if (!agents || agents.length === 0) {
    return null;
  }

  // Create a map of agents by ID
  const agentsById: Map<string, AgentNode> = new Map();
  
  agents.forEach(agent => {
    agentsById.set(agent.id, {
      id: agent.id,
      name: agent.name,
      type: agent.type,
      status: agent.status.toUpperCase() as AgentStatus,
      current_task: agent.current_task,
      task: agent.current_task,
      parent_id: agent.parent_id,
      tool_count: agent.tool_count,
      children: []
    });
  });

  // Build tree structure
  let root: AgentNode | null = null;

  agentsById.forEach((agent, id) => {
    const parentId = agent.parent_id;
    if (parentId && agentsById.has(parentId)) {
      const parent = agentsById.get(parentId)!;
      if (!parent.children) parent.children = [];
      parent.children.push(agent);
    } else {
      // This is a root node (no parent or parent not found)
      if (!root || agent.type === 'orchestrator') {
        root = agent;
      }
    }
  });

  return root;
}
