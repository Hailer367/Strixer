
import React from 'react';
import { ICONS } from '../constants';

interface Props {
  apiTotal: number;
  apiMinute: number;
  timeRemaining: number;
  vuls: number;
}

const StatsHeader: React.FC<Props> = ({ apiTotal, apiMinute, timeRemaining, vuls }) => {
  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  const ratePercent = (apiMinute / 60) * 100;

  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 p-4 border-b border-slate-800 bg-slate-950/80 backdrop-blur-xl z-10">
      <div className="flex items-center gap-4 bg-slate-900/50 p-3 rounded-xl border border-slate-800">
        <div className="p-2 bg-cyan-500/10 rounded-lg">
          <ICONS.Database className="w-5 h-5 text-cyan-400" />
        </div>
        <div>
          <p className="text-[10px] text-slate-400 uppercase font-bold tracking-widest">Total API Requests</p>
          <p className="text-xl font-bold text-slate-100 mono">{apiTotal.toLocaleString()}</p>
        </div>
      </div>

      <div className="bg-slate-900/50 p-3 rounded-xl border border-slate-800">
        <div className="flex justify-between items-center mb-2">
          <p className="text-[10px] text-slate-400 uppercase font-bold tracking-widest">Rate Limiter (60/m)</p>
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

      <div className="flex items-center gap-4 bg-slate-900/50 p-3 rounded-xl border border-slate-800">
        <div className="p-2 bg-amber-500/10 rounded-lg">
          <ICONS.Clock className="w-5 h-5 text-amber-400" />
        </div>
        <div>
          <p className="text-[10px] text-slate-400 uppercase font-bold tracking-widest">Session Time</p>
          <p className="text-xl font-bold text-slate-100 mono">{formatTime(timeRemaining)}</p>
        </div>
      </div>

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
  );
};

export default StatsHeader;
