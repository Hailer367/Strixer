import React, { useState, useEffect, useCallback } from 'react';
import { AgentNode, ReasoningLog, DashboardStats, StrixState, LiveFeedEntry, buildAgentTree } from './types';
import { ICONS, POLL_INTERVAL, API_BASE } from './constants';
import StatsHeader from './components/StatsHeader';
import AgentTreeNode from './components/AgentTreeNode';
import ReasoningFeed from './components/ReasoningFeed';
import { AreaChart, Area, ResponsiveContainer } from 'recharts';

interface ChartDataPoint {
  time: string;
  val: number;
}

type TabType = 'feed' | 'tree' | 'vulns';

const App: React.FC = () => {
  const [logs, setLogs] = useState<ReasoningLog[]>([]);
  const [stats, setStats] = useState<DashboardStats>({
    apiCallsTotal: 0,
    apiCallsMinute: 0,
    timeRemaining: 0,
    vulnerabilitiesFound: 0,
    activeAgents: 1,
    toolsExecuted: 0
  });
  const [chartData, setChartData] = useState<ChartDataPoint[]>([]);
  const [agentTree, setAgentTree] = useState<AgentNode | null>(null);
  const [scanConfig, setScanConfig] = useState<Partial<StrixState['scan_config']>>({});
  const [timeInfo, setTimeInfo] = useState<Partial<StrixState['time']>>({});
  const [vulnerabilities, setVulnerabilities] = useState<StrixState['vulnerabilities']>([]);
  const [connected, setConnected] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<TabType>('feed');
  const [lastError, setLastError] = useState<string | null>(null);

  // Fetch state from API
  const fetchState = useCallback(async () => {
    try {
      const [stateRes, treeRes] = await Promise.all([
        fetch(`${API_BASE}/api/state`),
        fetch(`${API_BASE}/api/agent-tree`)
      ]);

      if (!stateRes.ok || !treeRes.ok) {
        throw new Error(`API error: state=${stateRes.status}, tree=${treeRes.status}`);
      }

      const state: StrixState = await stateRes.json();
      const treeData = await treeRes.json();

      setConnected(true);
      setLastError(null);

      // Process agent tree - handle both formats (pre-built tree or flat array)
      if (treeData && typeof treeData === 'object') {
        if (treeData.id && treeData.name) {
          // Already a tree structure from backend
          setAgentTree(treeData as AgentNode);
        } else if (Array.isArray(treeData)) {
          // Flat array - build tree
          const builtTree = buildAgentTree(treeData);
          setAgentTree(builtTree);
        } else if (Object.keys(treeData).length > 0) {
          // Non-empty object that's not a tree - might be the root node
          setAgentTree(treeData as AgentNode);
        } else {
          // Empty object
          setAgentTree(null);
        }
      } else {
        setAgentTree(null);
      }

      // Also try to build tree from agents array in state if no tree from API
      if (!agentTree && state.agents && state.agents.length > 0) {
        const builtTree = buildAgentTree(state.agents);
        if (builtTree) {
          setAgentTree(builtTree);
        }
      }

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
          apiCallsTotal: state.stats.api_calls ?? prev.apiCallsTotal,
          vulnerabilitiesFound: state.stats.vulnerabilities_found ?? 0,
          activeAgents: state.stats.active_agents ?? 1,
          toolsExecuted: state.stats.tools_executed ?? 0,
          tokensUsed: state.stats.tokens_used,
          costUsd: state.stats.cost_usd
        }));
      }

      // Update vulnerabilities
      if (state.vulnerabilities) {
        setVulnerabilities(state.vulnerabilities);
      }

      // Update live feed - convert to ReasoningLog format
      if (state.live_feed && state.live_feed.length > 0) {
        const newLogs: ReasoningLog[] = state.live_feed.map((entry: LiveFeedEntry, idx: number) => ({
          id: entry.id || `log-${Date.now()}-${idx}`,
          timestamp: entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString(),
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
      setLastError(error instanceof Error ? error.message : 'Connection failed');
    }
  }, [agentTree]);

  // Poll for state updates
  useEffect(() => {
    fetchState();
    const interval = setInterval(fetchState, POLL_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchState]);

  // Handle tab change on mobile
  const handleTabChange = (tab: TabType) => {
    setActiveTab(tab);
    setMobileMenuOpen(false);
  };

  return (
    <div className="flex flex-col h-screen max-h-screen overflow-hidden bg-slate-950 text-slate-200 selection:bg-cyan-500/30">
      {/* Top Stats Bar */}
      <StatsHeader
        apiTotal={stats.apiCallsTotal}
        apiMinute={stats.apiCallsMinute}
        timeRemaining={stats.timeRemaining}
        vuls={stats.vulnerabilitiesFound}
        activeAgents={stats.activeAgents}
        toolsExecuted={stats.toolsExecuted}
      />

      {/* Mobile Navigation Bar */}
      <div className="lg:hidden flex items-center justify-between px-4 py-2 bg-slate-900/80 backdrop-blur-md border-b border-slate-800/50 z-30">
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${connected ? 'bg-cyan-400 animate-pulse shadow-[0_0_8px_#22d3ee]' : 'bg-red-500 shadow-[0_0_8px_#ef4444]'}`} />
          <span className="text-[10px] font-bold uppercase tracking-widest">
            {connected ? 'STRIX_LIVE' : 'DISCONNECTED'}
          </span>
        </div>
        
        {/* Mobile Tab Switcher */}
        <div className="flex items-center gap-1 bg-slate-950/50 rounded-lg p-0.5 border border-slate-800/50">
          <button
            onClick={() => handleTabChange('tree')}
            className={`p-2 rounded-md transition-all ${activeTab === 'tree' ? 'bg-cyan-500/20 text-cyan-400' : 'text-slate-500 hover:text-slate-300'}`}
            title="Agent Tree"
          >
            <ICONS.Shield className="w-4 h-4" />
          </button>
          <button
            onClick={() => handleTabChange('feed')}
            className={`p-2 rounded-md transition-all ${activeTab === 'feed' ? 'bg-cyan-500/20 text-cyan-400' : 'text-slate-500 hover:text-slate-300'}`}
            title="Activity Feed"
          >
            <ICONS.Activity className="w-4 h-4" />
          </button>
          <button
            onClick={() => handleTabChange('vulns')}
            className={`p-2 rounded-md transition-all ${activeTab === 'vulns' ? 'bg-cyan-500/20 text-cyan-400' : 'text-slate-500 hover:text-slate-300'}`}
            title="Vulnerabilities"
          >
            <ICONS.Target className="w-4 h-4" />
          </button>
        </div>

        {/* Menu button */}
        <button
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className="p-2 bg-slate-800/50 rounded-lg text-slate-400 hover:text-slate-200 transition-colors"
        >
          {mobileMenuOpen ? <ICONS.X className="w-5 h-5" /> : <ICONS.Menu className="w-5 h-5" />}
        </button>
      </div>

      {/* Mobile Menu Overlay */}
      {mobileMenuOpen && (
        <div className="lg:hidden fixed inset-0 z-40 bg-slate-950/98 backdrop-blur-xl flex flex-col animate-in fade-in duration-200">
          <div className="flex-1 p-6 space-y-6 overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-bold text-slate-100">Dashboard Menu</h2>
              <button
                onClick={() => setMobileMenuOpen(false)}
                className="p-2 bg-slate-800/50 rounded-lg text-slate-400"
              >
                <ICONS.X className="w-5 h-5" />
              </button>
            </div>

            {/* Quick Navigation */}
            <div className="space-y-2">
              <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-3">Navigation</p>
              <button
                onClick={() => handleTabChange('tree')}
                className={`w-full flex items-center gap-4 p-4 rounded-xl transition-all ${
                  activeTab === 'tree' ? 'bg-cyan-500/10 border border-cyan-500/30 text-cyan-400' : 'bg-slate-900/50 border border-slate-800 text-slate-300'
                }`}
              >
                <ICONS.Shield className="w-5 h-5" />
                <span className="font-bold">Agent Hierarchy</span>
              </button>
              <button
                onClick={() => handleTabChange('feed')}
                className={`w-full flex items-center gap-4 p-4 rounded-xl transition-all ${
                  activeTab === 'feed' ? 'bg-cyan-500/10 border border-cyan-500/30 text-cyan-400' : 'bg-slate-900/50 border border-slate-800 text-slate-300'
                }`}
              >
                <ICONS.Activity className="w-5 h-5" />
                <span className="font-bold">Activity Feed</span>
              </button>
              <button
                onClick={() => handleTabChange('vulns')}
                className={`w-full flex items-center gap-4 p-4 rounded-xl transition-all ${
                  activeTab === 'vulns' ? 'bg-cyan-500/10 border border-cyan-500/30 text-cyan-400' : 'bg-slate-900/50 border border-slate-800 text-slate-300'
                }`}
              >
                <ICONS.Target className="w-5 h-5" />
                <span className="font-bold">Vulnerabilities ({vulnerabilities.length})</span>
              </button>
            </div>

            {/* Quick Stats */}
            <div className="border-t border-slate-800 pt-6">
              <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-4">Scan Details</p>
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-slate-900/50 p-4 rounded-xl border border-slate-800">
                  <p className="text-[10px] text-slate-500 mb-1 uppercase">Target</p>
                  <p className="font-mono text-cyan-400 truncate text-sm">{scanConfig.target || '-'}</p>
                </div>
                <div className="bg-slate-900/50 p-4 rounded-xl border border-slate-800">
                  <p className="text-[10px] text-slate-500 mb-1 uppercase">Mode</p>
                  <p className="font-bold text-slate-100 text-sm uppercase">{scanConfig.scan_mode || 'deep'}</p>
                </div>
                <div className="bg-slate-900/50 p-4 rounded-xl border border-slate-800">
                  <p className="text-[10px] text-slate-500 mb-1 uppercase">Model</p>
                  <p className="font-mono text-slate-300 truncate text-sm">{scanConfig.model || '-'}</p>
                </div>
                <div className="bg-slate-900/50 p-4 rounded-xl border border-slate-800">
                  <p className="text-[10px] text-slate-500 mb-1 uppercase">Remaining</p>
                  <p className="font-bold text-slate-100 text-sm">{Math.round(timeInfo.remaining_minutes || 0)} min</p>
                </div>
              </div>
            </div>

            {/* Connection Status */}
            <div className="border-t border-slate-800 pt-6">
              <div className={`p-4 rounded-xl border ${connected ? 'bg-emerald-500/5 border-emerald-500/30' : 'bg-rose-500/5 border-rose-500/30'}`}>
                <div className="flex items-center gap-3">
                  <div className={`w-3 h-3 rounded-full ${connected ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500'}`} />
                  <div>
                    <p className="font-bold text-sm">{connected ? 'Connected' : 'Disconnected'}</p>
                    <p className="text-[10px] text-slate-500">
                      {connected ? `Polling every ${POLL_INTERVAL/1000}s` : lastError || 'Attempting to reconnect...'}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Main Content Area */}
      <div className="flex flex-1 overflow-hidden relative">
        {/* Left Sidebar: Agent Tree */}
        <aside className={`
          ${activeTab === 'tree' ? 'flex' : 'hidden'} lg:flex
          w-full lg:w-72 xl:w-80 flex-col border-r border-slate-800/50 bg-slate-950/60 backdrop-blur-md overflow-hidden
        `}>
          <div className="p-3 sm:p-4 flex-1 overflow-y-auto custom-scrollbar">
            <div className="flex items-center gap-2 mb-4 sm:mb-6 px-1 sm:px-2">
              <ICONS.Shield className="w-4 h-4 sm:w-5 sm:h-5 text-cyan-400" />
              <h2 className="text-[9px] sm:text-[10px] font-bold uppercase tracking-widest text-slate-400">Agent Hierarchy</h2>
              {stats.activeAgents > 0 && (
                <span className="ml-auto text-[8px] bg-cyan-500/10 text-cyan-400 px-2 py-0.5 rounded-full font-bold">
                  {stats.activeAgents} active
                </span>
              )}
            </div>

            <div className="space-y-2 sm:space-y-3">
              {agentTree ? (
                <AgentTreeNode node={agentTree} level={0} />
              ) : (
                <div className="text-center py-8 sm:py-10 space-y-3">
                  <div className="w-10 h-10 sm:w-12 sm:h-12 mx-auto rounded-full border-2 border-dashed border-slate-700 flex items-center justify-center">
                    <ICONS.Users className="w-4 h-4 sm:w-5 sm:h-5 text-slate-600" />
                  </div>
                  <p className="text-slate-600 text-[9px] sm:text-[10px] italic">
                    Waiting for agent orchestration...
                  </p>
                </div>
              )}
            </div>

            {/* Scan Config */}
            <div className="mt-6 sm:mt-8 border-t border-slate-800/50 pt-4 sm:pt-6 px-1 sm:px-2">
              <h3 className="text-[9px] sm:text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-3 sm:mb-4">Neural Config</h3>
              <div className="space-y-2 sm:space-y-3 text-[10px] sm:text-[11px]">
                <div className="flex justify-between items-center group">
                  <span className="text-slate-500">Target</span>
                  <span className="text-cyan-400 font-mono truncate max-w-[100px] sm:max-w-[140px] group-hover:text-cyan-300 transition-colors text-[9px] sm:text-[10px]">
                    {scanConfig.target || '-'}
                  </span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-500">Mode</span>
                  <span className="text-slate-300 px-2 py-0.5 bg-slate-800 rounded text-[8px] sm:text-[9px] uppercase font-bold">
                    {scanConfig.scan_mode || 'deep'}
                  </span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-500">Model</span>
                  <span className="text-slate-300 font-mono text-[8px] sm:text-[9px] truncate max-w-[100px] sm:max-w-[120px]">
                    {scanConfig.model || '-'}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Activity Chart */}
          <div className="p-3 sm:p-4 border-t border-slate-800/50 bg-slate-950/80">
            <h3 className="text-[9px] sm:text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2 sm:mb-3 ml-1 sm:ml-2">Tool Activity</h3>
            <div className="h-16 sm:h-20 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id="colorVal" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#22d3ee" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <Area 
                    type="monotone" 
                    dataKey="val" 
                    stroke="#22d3ee" 
                    strokeWidth={2} 
                    fillOpacity={1} 
                    fill="url(#colorVal)" 
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </aside>

        {/* Middle Section: Activity Feed */}
        <main className={`
          ${activeTab === 'feed' ? 'flex' : 'hidden'} lg:flex
          flex-1 flex-col min-w-0 bg-slate-900/20 backdrop-blur-sm relative
        `}>
          {/* Header */}
          <div className="flex items-center justify-between px-4 sm:px-6 py-3 sm:py-4 border-b border-slate-800/50 bg-slate-900/60 backdrop-blur-md sticky top-0 z-10">
            <div className="flex items-center gap-2 sm:gap-3">
              <ICONS.Terminal className="w-3 h-3 sm:w-4 sm:h-4 text-cyan-400" />
              <h2 className="text-[10px] sm:text-[11px] font-bold text-slate-300 uppercase tracking-widest">
                Neural Reasoning Feed
              </h2>
            </div>
            <div className="px-2 py-0.5 bg-cyan-500/10 border border-cyan-500/20 rounded-full">
              <span className="text-[8px] sm:text-[9px] text-cyan-400 font-bold mono">
                {logs.length} EVENTS
              </span>
            </div>
          </div>

          <ReasoningFeed logs={logs} />

          {/* Bottom Console Stats (Desktop only) */}
          <div className="hidden lg:flex h-8 sm:h-10 border-t border-slate-800/50 bg-slate-950 px-4 sm:px-6 items-center justify-between font-mono text-[8px] sm:text-[9px] uppercase tracking-tighter">
            <div className="flex gap-4 sm:gap-6 text-slate-500">
              <span className="flex items-center gap-2">
                <span className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-emerald-500' : 'bg-red-500 shadow-[0_0_8px_#ef4444]'}`} />
                {connected ? 'LINK_OK' : 'LINK_ERR'}
              </span>
              <span className="text-slate-600">POLL: {POLL_INTERVAL}ms</span>
              <span className="text-slate-600">MODEL: {scanConfig.model?.split('/')[0] || 'STRIX'}</span>
            </div>
            <div className="text-cyan-500/50 font-bold">
              STRIX_DASHBOARD_V2.1
            </div>
          </div>
        </main>

        {/* Right Sidebar: Vulnerabilities */}
        <aside className={`
          ${activeTab === 'vulns' ? 'flex' : 'hidden'} xl:flex
          w-full xl:w-72 2xl:w-80 flex-col border-l border-slate-800/50 bg-slate-950/60 backdrop-blur-md overflow-hidden
        `}>
          <div className="p-3 sm:p-4 flex-1 overflow-y-auto custom-scrollbar">
            <h2 className="text-[9px] sm:text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-4 sm:mb-6 flex items-center gap-2 px-1 sm:px-2">
              <ICONS.Target className="w-3 h-3 sm:w-4 sm:h-4 text-rose-500" />
              Detected Intel ({vulnerabilities.length})
            </h2>

            <div className="space-y-2 sm:space-y-3">
              {vulnerabilities.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 sm:py-16 text-slate-600 space-y-3 sm:space-y-4 border-2 border-dashed border-slate-800/50 rounded-xl mx-1 sm:mx-2">
                  <ICONS.Shield className="w-6 h-6 sm:w-8 sm:h-8 opacity-20" />
                  <div className="text-center space-y-1">
                    <p className="text-[9px] sm:text-[10px] uppercase tracking-widest font-bold opacity-50">No Vulnerabilities</p>
                    <p className="text-[8px] sm:text-[9px] opacity-30">Scan in progress...</p>
                  </div>
                </div>
              ) : (
                vulnerabilities.map((vuln, idx) => (
                  <div
                    key={vuln.id || idx}
                    className={`p-3 sm:p-4 rounded-xl border transition-all hover:scale-[1.01] cursor-default active:scale-[0.99] ${
                      vuln.severity === 'critical' ? 'bg-rose-500/5 border-rose-500/30 hover:bg-rose-500/10' :
                      vuln.severity === 'high' ? 'bg-orange-500/5 border-orange-500/30 hover:bg-orange-500/10' :
                      vuln.severity === 'medium' ? 'bg-amber-500/5 border-amber-500/30 hover:bg-amber-500/10' :
                      'bg-cyan-500/5 border-cyan-500/30 hover:bg-cyan-500/10'
                    }`}
                  >
                    <div className="flex justify-between items-start mb-2">
                      <span className={`text-[8px] sm:text-[9px] font-bold px-1.5 py-0.5 rounded uppercase ${
                        vuln.severity === 'critical' ? 'bg-rose-500 text-white' :
                        vuln.severity === 'high' ? 'bg-orange-500 text-white' :
                        vuln.severity === 'medium' ? 'bg-amber-500 text-slate-950' :
                        'bg-cyan-500 text-slate-950'
                      }`}>
                        {vuln.severity}
                      </span>
                      <span className="text-[8px] sm:text-[9px] font-mono text-slate-500 tracking-tighter">
                        {vuln.id}
                      </span>
                    </div>
                    <p className="text-[11px] sm:text-xs font-bold text-slate-100 mb-1 leading-tight">{vuln.title}</p>
                    {vuln.description && (
                      <p className="text-[9px] sm:text-[10px] text-slate-400 mb-2 line-clamp-2">{vuln.description}</p>
                    )}
                    <div className="flex items-center gap-1.5 opacity-60">
                      <ICONS.Activity className="w-2.5 h-2.5 sm:w-3 sm:h-3 text-slate-400" />
                      <p className="text-[8px] sm:text-[9px] text-slate-400 font-mono truncate">{vuln.endpoint}</p>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Time Progress Panel */}
          <div className="p-3 sm:p-4 border-t border-slate-800/50 bg-slate-950/80">
            <div className="bg-slate-900/60 p-3 sm:p-4 rounded-xl border border-slate-800/50">
              <p className="text-[8px] sm:text-[9px] text-slate-500 uppercase font-black tracking-widest mb-3 sm:mb-4">Scan Progress</p>
              <div className="space-y-3 sm:space-y-4">
                <div className="space-y-1">
                  <div className="flex justify-between text-[9px] sm:text-[10px]">
                    <span className="text-slate-400">Time Progress</span>
                    <span className="text-cyan-400 font-bold">{Math.round(timeInfo.progress_percentage || 0)}%</span>
                  </div>
                  <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full transition-all duration-1000 ${
                        timeInfo.is_critical ? 'bg-rose-500 shadow-[0_0_10px_#f43f5e]' :
                        timeInfo.is_warning ? 'bg-amber-500 shadow-[0_0_10px_#f59e0b]' :
                        'bg-cyan-500 shadow-[0_0_10px_#06b6d4]'
                      }`}
                      style={{ width: `${timeInfo.progress_percentage || 0}%` }}
                    />
                  </div>
                </div>
                <div className="flex items-center justify-between text-[9px] sm:text-[10px]">
                  <span className="text-slate-500">Phase:</span>
                  <span className={`font-bold ${timeInfo.is_critical ? 'text-rose-400 animate-pulse' : 'text-emerald-400'}`}>
                    {timeInfo.phase?.toUpperCase() || 'SCANNING'}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </aside>
      </div>

      {/* Global Styles */}
      <style dangerouslySetInnerHTML={{
        __html: `
        .custom-scrollbar::-webkit-scrollbar { width: 4px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 10px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #334155; }
        .line-clamp-2 {
          display: -webkit-box;
          -webkit-line-clamp: 2;
          -webkit-box-orient: vertical;
          overflow: hidden;
        }
      `}} />
    </div>
  );
};

export default App;
