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
  type: 'orchestrator' | 'scanner' | 'fuzzer' | 'exploiter' | 'reporter';
  status: AgentStatus;
  children?: AgentNode[];
  task?: string;
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
