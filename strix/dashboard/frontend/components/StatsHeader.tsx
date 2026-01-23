import React from 'react';
import { ICONS } from '../constants';

interface Props {
  apiTotal: number;
  apiMinute: number;
  timeRemaining: number;
  vuls: number;
  activeAgents?: number;
  toolsExecuted?: number;
}

const StatsHeader: React.FC<Props> = ({ 
  apiTotal, 
  apiMinute, 
  timeRemaining, 
  vuls,
  activeAgents = 1,
  toolsExecuted = 0
}) => {
  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  const ratePercent = (apiMinute / 60) * 100;

  return (
    <div className="bg-slate-950/80 backdrop-blur-xl border-b border-slate-800 z-10">
      {/* Mobile Stats - Compact Grid */}
      <div className="lg:hidden p-3">
        <div className="grid grid-cols-2 gap-2">
          {/* Time Remaining - Full Width on Mobile */}
          <div className="col-span-2 flex items-center justify-between bg-slate-900/50 p-3 rounded-xl border border-slate-800">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-amber-500/10 rounded-lg">
                <ICONS.Clock className="w-4 h-4 text-amber-400" />
              </div>
              <div>
                <p className="text-[9px] text-slate-400 uppercase font-bold tracking-widest">Session Time</p>
                <p className="text-lg font-bold text-slate-100 mono">{formatTime(timeRemaining)}</p>
              </div>
            </div>
            <div className="text-right">
              <p className="text-[9px] text-slate-400 uppercase font-bold">Agents</p>
              <p className="text-lg font-bold text-cyan-400 mono">{activeAgents}</p>
            </div>
          </div>

          {/* Vulnerabilities */}
          <div className="flex items-center gap-2 bg-slate-900/50 p-3 rounded-xl border border-slate-800">
            <div className="p-1.5 bg-rose-500/10 rounded-lg">
              <ICONS.Target className="w-4 h-4 text-rose-400" />
            </div>
            <div>
              <p className="text-[8px] text-slate-400 uppercase font-bold">Vulns</p>
              <p className="text-lg font-bold text-rose-400 mono">{vuls}</p>
            </div>
          </div>

          {/* API Calls */}
          <div className="flex items-center gap-2 bg-slate-900/50 p-3 rounded-xl border border-slate-800">
            <div className="p-1.5 bg-cyan-500/10 rounded-lg">
              <ICONS.Database className="w-4 h-4 text-cyan-400" />
            </div>
            <div>
              <p className="text-[8px] text-slate-400 uppercase font-bold">API Calls</p>
              <p className="text-lg font-bold text-slate-100 mono">{apiTotal.toLocaleString()}</p>
            </div>
          </div>

          {/* Tools Executed */}
          <div className="flex items-center gap-2 bg-slate-900/50 p-3 rounded-xl border border-slate-800">
            <div className="p-1.5 bg-purple-500/10 rounded-lg">
              <ICONS.Tool className="w-4 h-4 text-purple-400" />
            </div>
            <div>
              <p className="text-[8px] text-slate-400 uppercase font-bold">Tools</p>
              <p className="text-lg font-bold text-purple-400 mono">{toolsExecuted}</p>
            </div>
          </div>

          {/* Rate Limiter */}
          <div className="flex items-center gap-2 bg-slate-900/50 p-3 rounded-xl border border-slate-800">
            <div className="p-1.5 bg-emerald-500/10 rounded-lg">
              <ICONS.Activity className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="flex-1">
              <p className="text-[8px] text-slate-400 uppercase font-bold">Rate</p>
              <p className={`text-lg font-bold mono ${apiMinute > 50 ? 'text-rose-400' : 'text-emerald-400'}`}>
                {apiMinute}/60
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Desktop Stats - Full Grid */}
      <div className="hidden lg:grid lg:grid-cols-5 gap-4 p-4">
        {/* API Calls */}
        <div className="flex items-center gap-4 bg-slate-900/50 p-3 rounded-xl border border-slate-800">
          <div className="p-2 bg-cyan-500/10 rounded-lg">
            <ICONS.Database className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <p className="text-[10px] text-slate-400 uppercase font-bold tracking-widest">API Calls</p>
            <p className="text-xl font-bold text-slate-100 mono">{apiTotal.toLocaleString()}</p>
          </div>
        </div>

        {/* Rate Limiter */}
        <div className="bg-slate-900/50 p-3 rounded-xl border border-slate-800">
          <div className="flex justify-between items-center mb-2">
            <p className="text-[10px] text-slate-400 uppercase font-bold tracking-widest">Rate (60/m)</p>
            <span className={`text-[10px] mono font-bold ${apiMinute > 50 ? 'text-rose-400' : 'text-cyan-400'}`}>
              {apiMinute}/60
            </span>
          </div>
          <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
            <div 
              className={`h-full transition-all duration-500 ${apiMinute > 50 ? 'bg-rose-500' : 'bg-cyan-500'}`}
              style={{ width: `${Math.min(100, ratePercent)}%` }}
            />
          </div>
        </div>

        {/* Session Time */}
        <div className="flex items-center gap-4 bg-slate-900/50 p-3 rounded-xl border border-slate-800">
          <div className="p-2 bg-amber-500/10 rounded-lg">
            <ICONS.Clock className="w-5 h-5 text-amber-400" />
          </div>
          <div>
            <p className="text-[10px] text-slate-400 uppercase font-bold tracking-widest">Session Time</p>
            <p className="text-xl font-bold text-slate-100 mono">{formatTime(timeRemaining)}</p>
          </div>
        </div>

        {/* Tools Executed */}
        <div className="flex items-center gap-4 bg-slate-900/50 p-3 rounded-xl border border-slate-800">
          <div className="p-2 bg-purple-500/10 rounded-lg">
            <ICONS.Tool className="w-5 h-5 text-purple-400" />
          </div>
          <div>
            <p className="text-[10px] text-slate-400 uppercase font-bold tracking-widest">Tools Run</p>
            <p className="text-xl font-bold text-purple-400 mono">{toolsExecuted}</p>
          </div>
        </div>

        {/* Vulnerabilities */}
        <div className="flex items-center gap-4 bg-slate-900/50 p-3 rounded-xl border border-slate-800">
          <div className="p-2 bg-rose-500/10 rounded-lg">
            <ICONS.Target className="w-5 h-5 text-rose-400" />
          </div>
          <div>
            <p className="text-[10px] text-slate-400 uppercase font-bold tracking-widest">Vulns Found</p>
            <p className="text-xl font-bold text-rose-400 mono">{vuls}</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default StatsHeader;
