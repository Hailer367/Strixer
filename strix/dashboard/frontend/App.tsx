import React, { useState, useEffect, useCallback } from 'react';
import { AgentNode, ReasoningLog, DashboardStats, StrixState } from './types';
import { INITIAL_AGENT_TREE, ICONS } from './constants';
import StatsHeader from './components/StatsHeader';
import AgentTreeNode from './components/AgentTreeNode';
import ReasoningFeed from './components/ReasoningFeed';
import { AreaChart, Area, ResponsiveContainer } from 'recharts';

const API_BASE = '';  // Same origin
const POLL_INTERVAL = 2000;  // 2 seconds

interface ChartDataPoint {
  time: string;
  val: number;
}

const App: React.FC = () => {
  const [logs, setLogs] = useState<ReasoningLog[]>([]);
  const [stats, setStats] = useState<DashboardStats>({
    apiCallsTotal: 0,
    apiCallsMinute: 0,
    timeRemaining: 0,
    vulnerabilitiesFound: 0,
    activeAgents: 1
  });
  const [chartData, setChartData] = useState<ChartDataPoint[]>([]);
  const [agentTree] = useState<AgentNode>(INITIAL_AGENT_TREE);
  const [scanConfig, setScanConfig] = useState<Partial<StrixState['scan_config']>>({});
  const [timeInfo, setTimeInfo] = useState<Partial<StrixState['time']>>({});
  const [vulnerabilities, setVulnerabilities] = useState<StrixState['vulnerabilities']>([]);
  const [connected, setConnected] = useState(false);

  // Fetch state from API
  const fetchState = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/api/state`);
      if (!response.ok) throw new Error('API error');

      const state: StrixState = await response.json();
      setConnected(true);

      // Update scan config
      if (state.scan_config) {
        setScanConfig(state.scan_config);
      }

      // Update time info
      if (state.time) {
        setTimeInfo(state.time);
        setStats(prev => ({
          ...prev,
          timeRemaining: Math.round((state.time.remaining_minutes || 0) * 60)
        }));
      }

      // Update stats
      if (state.stats) {
        setStats(prev => ({
          ...prev,
          apiCallsTotal: state.stats.api_calls || prev.apiCallsTotal,
          vulnerabilitiesFound: state.stats.vulnerabilities_found || 0,
          activeAgents: state.stats.active_agents || 1
        }));
      }

      // Update vulnerabilities
      if (state.vulnerabilities) {
        setVulnerabilities(state.vulnerabilities);
      }

      // Update live feed as logs
      if (state.live_feed) {
        const newLogs: ReasoningLog[] = state.live_feed.map((entry, idx) => ({
          id: entry.id || `log-${idx}`,
          timestamp: new Date(entry.timestamp).toLocaleTimeString(),
          thought: entry.message || '',
          tool: entry.tool || '',
          toolInput: entry.input || '',
          toolOutput: entry.output || '',
          action: entry.type || 'info',
          severity: (entry.severity || 'info') as ReasoningLog['severity']
        }));
        setLogs(newLogs);
      }

      // Update tool executions as logs
      if (state.tool_executions && state.tool_executions.length > 0) {
        const toolLogs: ReasoningLog[] = state.tool_executions.slice(-20).map((t) => ({
          id: t.id,
          timestamp: new Date(t.timestamp).toLocaleTimeString(),
          thought: `Executing ${t.tool}`,
          tool: t.tool,
          toolInput: t.input,
          toolOutput: t.output,
          action: t.status === 'success' ? 'completed' : 'error',
          severity: (t.status === 'success' ? 'info' : 'high') as ReasoningLog['severity']
        }));
        setLogs(prev => [...toolLogs, ...prev.slice(0, 30)]);
      }

      // Update chart data
      setChartData(prev => {
        const newPoint: ChartDataPoint = {
          time: new Date().toLocaleTimeString(),
          val: state.stats?.tools_executed || Math.floor(Math.random() * 60)
        };
        const newData = [...prev, newPoint];
        return newData.length > 20 ? newData.slice(-20) : newData;
      });

    } catch (error) {
      console.error('Failed to fetch state:', error);
      setConnected(false);
    }
  }, []);

  // Poll for state updates
  useEffect(() => {
    fetchState();
    const interval = setInterval(fetchState, POLL_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchState]);

  return (
    <div className="flex flex-col h-screen max-h-screen overflow-hidden bg-slate-950 text-slate-200">
      {/* Top Stats Bar */}
      <StatsHeader
        apiTotal={stats.apiCallsTotal}
        apiMinute={stats.apiCallsMinute}
        timeRemaining={stats.timeRemaining}
        vuls={stats.vulnerabilitiesFound}
      />

      <div className="flex flex-1 overflow-hidden">
        {/* Left Sidebar: Agent Tree */}
        <aside className="w-80 border-r border-slate-800 bg-slate-950/40 overflow-y-auto p-4 hidden lg:block">
          <div className="flex items-center gap-2 mb-6 px-2">
            <ICONS.Shield className="w-5 h-5 text-cyan-400" />
            <h2 className="text-xs font-bold uppercase tracking-widest text-slate-400">Agent Hierarchy</h2>
          </div>
          <div className="space-y-4">
            <AgentTreeNode node={agentTree} level={0} />
          </div>

          {/* Scan Config */}
          <div className="mt-6 border-t border-slate-800 pt-4 px-2">
            <h3 className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-3">Scan Config</h3>
            <div className="space-y-2 text-xs">
              <div className="flex justify-between">
                <span className="text-slate-500">Target:</span>
                <span className="text-cyan-400 font-mono truncate max-w-[150px]">{scanConfig.target || '-'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Mode:</span>
                <span className="text-slate-300">{scanConfig.scan_mode || 'deep'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Model:</span>
                <span className="text-slate-300">{scanConfig.model || 'qwen3-coder-plus'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Timeframe:</span>
                <span className="text-slate-300">{scanConfig.timeframe || 60} min</span>
              </div>
            </div>
          </div>

          {/* Time Progress */}
          <div className="mt-4 px-2">
            <div className="flex justify-between text-[10px] text-slate-500 mb-1">
              <span>Progress</span>
              <span>{Math.round(timeInfo.progress_percentage || 0)}%</span>
            </div>
            <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
              <div
                className={`h-full transition-all ${timeInfo.is_critical ? 'bg-red-500' :
                  timeInfo.is_warning ? 'bg-amber-500' : 'bg-cyan-500'
                  }`}
                style={{ width: `${timeInfo.progress_percentage || 0}%` }}
              />
            </div>
            <div className="text-[10px] text-center mt-1 text-slate-400">
              {timeInfo.phase?.toUpperCase() || 'RUNNING'}
            </div>
          </div>

          <div className="mt-6 border-t border-slate-800 pt-4 px-2">
            <h3 className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-4">Tool Activity</h3>
            <div className="h-32 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id="colorVal" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#22d3ee" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <Area type="monotone" dataKey="val" stroke="#22d3ee" fillOpacity={1} fill="url(#colorVal)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </aside>

        {/* Middle Section: Main Agent Reasoning Feed */}
        <main className="flex-1 flex flex-col min-w-0 bg-slate-900/20 backdrop-blur-md">
          <div className="flex items-center justify-between px-6 py-3 border-b border-slate-800 bg-slate-900/40">
            <div className="flex items-center gap-3">
              <div className={`w-2 h-2 rounded-full ${connected ? 'bg-cyan-400 animate-pulse' : 'bg-red-500'}`}></div>
              <h2 className="text-sm font-bold text-slate-200 uppercase tracking-widest">
                {connected ? 'Live Activity Feed' : 'Connecting...'}
              </h2>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-slate-500">
                {logs.length} events
              </span>
            </div>
          </div>

          <ReasoningFeed logs={logs} />

          {/* Bottom Terminal-ish Stats */}
          <div className="h-12 border-t border-slate-800 bg-slate-950 px-6 flex items-center justify-between font-mono text-[10px]">
            <div className="flex gap-6 text-slate-500">
              <span className="flex items-center gap-2">
                <span className={`w-1 h-1 rounded-full ${connected ? 'bg-emerald-500' : 'bg-red-500'}`}></span>
                {connected ? 'CONNECTED' : 'DISCONNECTED'}
              </span>
              <span className="flex items-center gap-2">
                <span className="w-1 h-1 rounded-full bg-cyan-500"></span>
                POLL: {POLL_INTERVAL}ms
              </span>
              <span className="flex items-center gap-2">
                <span className="w-1 h-1 rounded-full bg-purple-500"></span>
                {scanConfig.model || 'QWEN'}
              </span>
            </div>
            <div className="text-cyan-400">
              STRIX_DASHBOARD // PORT_8080
            </div>
          </div>
        </main>

        {/* Right Sidebar: Vulnerability Tracker */}
        <aside className="w-72 border-l border-slate-800 bg-slate-950/40 p-4 hidden xl:block overflow-y-auto">
          <h2 className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-6 flex items-center gap-2">
            <ICONS.Target className="w-4 h-4 text-rose-500" />
            Vulnerabilities ({vulnerabilities.length})
          </h2>

          <div className="space-y-3">
            {vulnerabilities.length === 0 ? (
              <div className="text-slate-500 text-xs text-center py-8">
                No vulnerabilities found yet
              </div>
            ) : (
              vulnerabilities.map((vuln, idx) => (
                <div key={vuln.id || idx} className={`p-3 rounded-lg border ${vuln.severity === 'critical' ? 'bg-rose-500/10 border-rose-500/20' :
                  vuln.severity === 'high' ? 'bg-orange-500/10 border-orange-500/20' :
                    vuln.severity === 'medium' ? 'bg-amber-500/10 border-amber-500/20' :
                      'bg-cyan-500/10 border-cyan-500/20'
                  }`}>
                  <div className="flex justify-between items-start mb-1">
                    <span className={`text-[10px] font-bold uppercase ${vuln.severity === 'critical' ? 'text-rose-400' :
                      vuln.severity === 'high' ? 'text-orange-400' :
                        vuln.severity === 'medium' ? 'text-amber-400' :
                          'text-cyan-400'
                      }`}>{vuln.severity}</span>
                    <span className="text-[9px] font-mono text-slate-500">{vuln.id}</span>
                  </div>
                  <p className="text-xs font-bold text-slate-200 mb-1">{vuln.title}</p>
                  <p className="text-[10px] text-slate-400 font-mono truncate">{vuln.endpoint}</p>
                </div>
              ))
            )}
          </div>

          <div className="mt-8">
            <h2 className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-4 flex items-center gap-2">
              <ICONS.AlertCircle className="w-4 h-4 text-cyan-400" />
              Target Info
            </h2>
            <div className="bg-slate-900/60 p-4 rounded-xl border border-slate-800 space-y-4">
              <div>
                <p className="text-[9px] text-slate-500 uppercase font-bold tracking-tighter">Target</p>
                <p className="text-xs text-slate-300 font-mono truncate">{scanConfig.target || '-'}</p>
              </div>
              <div>
                <p className="text-[9px] text-slate-500 uppercase font-bold tracking-tighter">Scan Mode</p>
                <p className="text-xs text-slate-300">{scanConfig.scan_mode || 'deep'}</p>
              </div>
              <div>
                <p className="text-[9px] text-slate-500 uppercase font-bold tracking-tighter">Time Remaining</p>
                <p className={`text-xs font-bold ${timeInfo.is_critical ? 'text-red-400' :
                  timeInfo.is_warning ? 'text-amber-400' : 'text-cyan-400'
                  }`}>
                  {Math.round(timeInfo.remaining_minutes || 0)} min
                </p>
              </div>
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
};

export default App;
