import React, { useState, useEffect, useCallback } from 'react';
import { AgentNode, ReasoningLog, DashboardStats, StrixState, LiveFeedEntry } from './types';
import { ICONS } from './constants';
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
  const [agentTree, setAgentTree] = useState<AgentNode | null>(null);
  const [scanConfig, setScanConfig] = useState<Partial<StrixState['scan_config']>>({});
  const [timeInfo, setTimeInfo] = useState<Partial<StrixState['time']>>({});
  const [vulnerabilities, setVulnerabilities] = useState<StrixState['vulnerabilities']>([]);
  const [connected, setConnected] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<'feed' | 'tree' | 'vulns'>('feed');

  // Fetch state from API
  const fetchState = useCallback(async () => {
    try {
      const [stateRes, treeRes] = await Promise.all([
        fetch(`${API_BASE}/api/state`),
        fetch(`${API_BASE}/api/agent-tree`)
      ]);

      if (!stateRes.ok || !treeRes.ok) throw new Error('API error');

      const state: StrixState = await stateRes.json();
      const tree: AgentNode = await treeRes.json();

      setConnected(true);
      setAgentTree(Object.keys(tree).length > 0 ? tree : null);

      // Update scan config
      if (state.scan_config) setScanConfig(state.scan_config);

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
      if (state.vulnerabilities) setVulnerabilities(state.vulnerabilities);

      // Update live feed
      if (state.live_feed) {
        const newLogs: ReasoningLog[] = state.live_feed.map((entry: LiveFeedEntry, idx: number) => ({
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

      // Refresh chart data
      setChartData(prev => {
        const newPoint: ChartDataPoint = {
          time: new Date().toLocaleTimeString(),
          val: state.stats?.tools_executed || 0
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
    <div className="flex flex-col h-screen max-h-screen overflow-hidden bg-slate-950 text-slate-200 selection:bg-cyan-500/30">
      {/* Top Stats Bar */}
      <StatsHeader
        apiTotal={stats.apiCallsTotal}
        apiMinute={stats.apiCallsMinute}
        timeRemaining={stats.timeRemaining}
        vuls={stats.vulnerabilitiesFound}
      />

      {/* Mobile Navigation */}
      <div className="lg:hidden flex items-center justify-between px-6 py-3 bg-slate-900/80 backdrop-blur-md border-b border-slate-800 z-50">
        <div className="flex items-center gap-3">
          <div className={`w-2 h-2 rounded-full ${connected ? 'bg-cyan-400 animate-pulse' : 'bg-red-500'}`}></div>
          <span className="text-xs font-bold uppercase tracking-widest">{connected ? 'STRIX_LIVE' : 'DISCONNECTED'}</span>
        </div>
        <button
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className="p-2 bg-slate-800 rounded-lg text-slate-400"
        >
          {mobileMenuOpen ? <ICONS.Zap className="w-5 h-5 text-cyan-400" /> : <ICONS.Activity className="w-5 h-5" />}
        </button>
      </div>

      {/* Mobile Menu Overlay */}
      {mobileMenuOpen && (
        <div className="lg:hidden fixed inset-0 z-40 bg-slate-950/95 backdrop-blur-xl flex flex-col p-8 space-y-8 animate-in fade-in duration-300">
          <button
            onClick={() => { setActiveTab('tree'); setMobileMenuOpen(false); }}
            className={`flex items-center gap-4 text-lg font-bold ${activeTab === 'tree' ? 'text-cyan-400' : 'text-slate-400'}`}
          >
            <ICONS.Shield className="w-6 h-6" /> AGENT HIERARCHY
          </button>
          <button
            onClick={() => { setActiveTab('feed'); setMobileMenuOpen(false); }}
            className={`flex items-center gap-4 text-lg font-bold ${activeTab === 'feed' ? 'text-cyan-400' : 'text-slate-400'}`}
          >
            <ICONS.Activity className="w-6 h-6" /> ACTIVITY FEED
          </button>
          <button
            onClick={() => { setActiveTab('vulns'); setMobileMenuOpen(false); }}
            className={`flex items-center gap-4 text-lg font-bold ${activeTab === 'vulns' ? 'text-cyan-400' : 'text-slate-400'}`}
          >
            <ICONS.Target className="w-6 h-6" /> VULNERABILITIES
          </button>

          <div className="mt-auto border-t border-slate-800 pt-8">
            <h3 className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-4">Quick Stats</h3>
            <div className="grid grid-cols-2 gap-4 text-xs">
              <div className="bg-slate-900/50 p-4 rounded-xl border border-slate-800">
                <p className="text-slate-500 mb-1">Target</p>
                <p className="font-mono text-cyan-400 truncate">{scanConfig.target || '-'}</p>
              </div>
              <div className="bg-slate-900/50 p-4 rounded-xl border border-slate-800">
                <p className="text-slate-500 mb-1">Time</p>
                <p className="font-bold text-slate-100">{Math.round(timeInfo.remaining_minutes || 0)} min</p>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="flex flex-1 overflow-hidden relative">
        {/* Left Sidebar: Agent Tree */}
        <aside className={`
          ${activeTab === 'tree' ? 'flex' : 'hidden'} lg:flex
          w-full lg:w-80 flex-col border-r border-slate-800/50 bg-slate-950/40 backdrop-blur-md overflow-hidden
        `}>
          <div className="p-4 flex-1 overflow-y-auto custom-scrollbar">
            <div className="flex items-center gap-2 mb-6 px-2">
              <ICONS.Shield className="w-5 h-5 text-cyan-400" />
              <h2 className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Agent Hierarchy</h2>
            </div>

            <div className="space-y-4">
              {agentTree ? (
                <AgentTreeNode node={agentTree} level={0} />
              ) : (
                <div className="text-center py-10 text-slate-600 text-[10px] italic">
                  Waiting for agent orchestration...
                </div>
              )}
            </div>

            {/* Scan Config */}
            <div className="mt-8 border-t border-slate-800 pt-6 px-2">
              <h3 className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-4">Neural Config</h3>
              <div className="space-y-3 text-[11px]">
                <div className="flex justify-between items-center group">
                  <span className="text-slate-500">Target</span>
                  <span className="text-cyan-400 font-mono truncate max-w-[140px] group-hover:text-cyan-300 transition-colors uppercase">{scanConfig.target || '-'}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-500">Modality</span>
                  <span className="text-slate-300 px-2 py-0.5 bg-slate-800 rounded text-[9px] uppercase font-bold">{scanConfig.scan_mode || 'deep'}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-500">Engine</span>
                  <span className="text-slate-300 font-mono text-[9px]">{scanConfig.model || 'qwen-32b'}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Activity Chart Overlay */}
          <div className="p-4 border-t border-slate-800/50 bg-slate-950/60">
            <h3 className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-3 ml-2">Tool Frequency</h3>
            <div className="h-24 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id="colorVal" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#22d3ee" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <Area type="monotone" dataKey="val" stroke="#22d3ee" strokeWidth={2} fillOpacity={1} fill="url(#colorVal)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </aside>

        {/* Middle Section: Main Agent Reasoning Feed */}
        <main className={`
          ${activeTab === 'feed' ? 'flex' : 'hidden'} lg:flex
          flex-1 flex-col min-w-0 bg-slate-900/10 backdrop-blur-sm relative
        `}>
          {/* Subtle Grid Background */}
          <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20 pointer-events-none"></div>

          <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800/50 bg-slate-900/40 backdrop-blur-md sticky top-0 z-10">
            <div className="flex items-center gap-3">
              <ICONS.Terminal className="w-4 h-4 text-cyan-400" />
              <h2 className="text-[11px] font-bold text-slate-300 uppercase tracking-widest">
                Strix Neural Reasoning Feed
              </h2>
            </div>
            <div className="px-2 py-0.5 bg-cyan-500/10 border border-cyan-500/20 rounded-full">
              <span className="text-[9px] text-cyan-400 font-bold mono">
                {logs.length} EVENTS_PARSED
              </span>
            </div>
          </div>

          <ReasoningFeed logs={logs} />

          {/* Bottom Console Stats */}
          <div className="hidden lg:flex h-10 border-t border-slate-800/50 bg-slate-950 px-6 items-center justify-between font-mono text-[9px] uppercase tracking-tighter">
            <div className="flex gap-6 text-slate-500">
              <span className="flex items-center gap-2">
                <span className={`w-1 h-1 rounded-full ${connected ? 'bg-emerald-500' : 'bg-red-500 shadow-[0_0_8px_#ef4444]'}`}></span>
                {connected ? 'LINK_ESTABLISHED' : 'LINK_BROKEN'}
              </span>
              <span className="text-slate-600">POLL_MS: {POLL_INTERVAL}</span>
              <span className="text-slate-600">CORE: {scanConfig.model?.split('/')[0] || 'STRIX'}</span>
            </div>
            <div className="text-cyan-500/60 font-bold">
              SENTINEL_DASHBOARD_V2.0 // TERMINAL_ID_{Math.floor(Math.random() * 1000)}
            </div>
          </div>
        </main>

        {/* Right Sidebar: Vulnerability Tracker */}
        <aside className={`
          ${activeTab === 'vulns' ? 'flex' : 'hidden'} xl:flex
          w-full xl:w-80 flex-col border-l border-slate-800/50 bg-slate-950/40 backdrop-blur-md p-4 overflow-y-auto custom-scrollbar
        `}>
          <h2 className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-6 flex items-center gap-2 px-2">
            <ICONS.Target className="w-4 h-4 text-rose-500" />
            Detected Intel ({vulnerabilities.length})
          </h2>

          <div className="space-y-3">
            {vulnerabilities.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-20 text-slate-600 space-y-4 border-2 border-dashed border-slate-800/50 rounded-2xl mx-2">
                <ICONS.Shield className="w-8 h-8 opacity-20" />
                <p className="text-[9px] uppercase tracking-widest font-bold opacity-50">Passive Recon Active</p>
              </div>
            ) : (
              vulnerabilities.map((vuln, idx) => (
                <div
                  key={vuln.id || idx}
                  className={`p-4 rounded-xl border transition-all hover:scale-[1.02] cursor-default active:scale-[0.98] ${vuln.severity === 'critical' ? 'bg-rose-500/5 border-rose-500/30 hover:bg-rose-500/10' :
                      vuln.severity === 'high' ? 'bg-orange-500/5 border-orange-500/30 hover:bg-orange-500/10' :
                        vuln.severity === 'medium' ? 'bg-amber-500/5 border-amber-500/30 hover:bg-amber-500/10' :
                          'bg-cyan-500/5 border-cyan-500/30 hover:bg-cyan-500/10'
                    }`}
                >
                  <div className="flex justify-between items-start mb-2">
                    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded uppercase ${vuln.severity === 'critical' ? 'bg-rose-500 text-white' :
                        vuln.severity === 'high' ? 'bg-orange-500 text-white' :
                          vuln.severity === 'medium' ? 'bg-amber-500 text-slate-950' :
                            'bg-cyan-500 text-slate-950'
                      }`}>{vuln.severity}</span>
                    <span className="text-[9px] font-mono text-slate-500 tracking-tighter">SIG_{vuln.id}</span>
                  </div>
                  <p className="text-xs font-bold text-slate-100 mb-1 leading-tight">{vuln.title}</p>
                  <div className="flex items-center gap-1.5 opacity-60">
                    <ICONS.Activity className="w-3 h-3 text-slate-400" />
                    <p className="text-[9px] text-slate-400 font-mono truncate">{vuln.endpoint}</p>
                  </div>
                </div>
              ))
            )}
          </div>

          <div className="mt-auto pt-8 px-2 space-y-4">
            <div className="bg-slate-900/60 p-5 rounded-2xl border border-slate-800/50 shadow-2xl">
              <p className="text-[9px] text-slate-500 uppercase font-black tracking-widest mb-4">Neural Synthesis</p>
              <div className="space-y-4">
                <div className="space-y-1">
                  <div className="flex justify-between text-[10px]">
                    <span className="text-slate-400">Time Progress</span>
                    <span className="text-cyan-400 font-bold">{Math.round(timeInfo.progress_percentage || 0)}%</span>
                  </div>
                  <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full transition-all duration-1000 ${timeInfo.is_critical ? 'bg-rose-500 shadow-[0_0_10px_#f43f5e]' :
                          timeInfo.is_warning ? 'bg-amber-500 shadow-[0_0_10px_#f59e0b]' :
                            'bg-cyan-500 shadow-[0_0_10px_#06b6d4]'
                        }`}
                      style={{ width: `${timeInfo.progress_percentage || 0}%` }}
                    />
                  </div>
                </div>
                <div className="flex items-center justify-between text-[10px]">
                  <span className="text-slate-500">Operation Status:</span>
                  <span className={`font-bold animate-pulse ${timeInfo.is_critical ? 'text-rose-400' : 'text-emerald-400'}`}>
                    {timeInfo.phase?.toUpperCase() || 'SEARCHING'}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </aside>
      </div>

      <style dangerouslySetInnerHTML={{
        __html: `
        .custom-scrollbar::-webkit-scrollbar { width: 4px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 10px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #334155; }
      `}} />
    </div>
  );
};

export default App;
