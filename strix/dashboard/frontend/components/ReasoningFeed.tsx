
import React, { useEffect, useRef } from 'react';
import { ReasoningLog } from '../types';

interface Props {
  logs: ReasoningLog[];
}

const ReasoningFeed: React.FC<Props> = ({ logs }) => {
  const feedEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    feedEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const getSeverityGlow = (severity?: string) => {
    switch (severity) {
      case 'critical': return 'shadow-[0_0_15px_rgba(244,63,94,0.15)] border-rose-500/30';
      case 'high': return 'shadow-[0_0_15px_rgba(249,115,22,0.15)] border-orange-500/30';
      case 'medium': return 'shadow-[0_0_15px_rgba(245,158,11,0.15)] border-amber-500/30';
      default: return 'shadow-[0_0_15px_rgba(34,211,238,0.1)] border-slate-800';
    }
  };

  return (
    <div className="flex-1 overflow-y-auto px-4 py-6 space-y-8 scroll-smooth">
      {logs.length === 0 && (
        <div className="flex flex-col items-center justify-center h-full text-slate-500 space-y-4">
          <div className="w-12 h-12 rounded-full border-2 border-slate-700 border-t-cyan-500 animate-spin" />
          <p className="animate-pulse font-mono uppercase tracking-widest text-[10px]">Synchronizing Neural Context...</p>
        </div>
      )}
      
      {logs.map((log) => (
        <div key={log.id} className={`flex flex-col gap-3 group animate-in fade-in slide-in-from-bottom-4 duration-700`}>
          {/* Header & Thought */}
          <div className="flex gap-4 items-start">
            <div className="flex-shrink-0 mt-1">
              <div className={`w-2 h-2 rounded-full ${
                log.severity === 'critical' ? 'bg-rose-500 animate-pulse' : 
                log.severity === 'high' ? 'bg-orange-500' : 'bg-cyan-500'
              }`}></div>
            </div>
            <div className="flex-1 space-y-2">
              <div className="flex items-center gap-3">
                <span className="text-[10px] font-mono text-slate-500">[{log.timestamp}]</span>
                <span className="text-[10px] font-bold uppercase tracking-widest text-cyan-500/80">REASONING_ENGINE</span>
                <span className="h-[1px] flex-1 bg-slate-800/50"></span>
                <span className={`text-[9px] px-1.5 py-0.5 rounded border font-bold uppercase ${
                  log.severity === 'critical' ? 'border-rose-500/50 text-rose-400 bg-rose-500/10' : 
                  'border-slate-700 text-slate-400 bg-slate-800/40'
                }`}>
                  {log.severity}
                </span>
              </div>
              <p className="text-sm text-slate-300 leading-relaxed italic border-l-2 border-slate-800 pl-4 py-1">
                {log.thought}
              </p>
            </div>
          </div>

          {/* Terminal Block */}
          <div className={`ml-6 rounded-lg overflow-hidden border bg-[#030712] ${getSeverityGlow(log.severity)}`}>
            {/* Terminal Header */}
            <div className="bg-slate-900/80 px-4 py-2 flex items-center justify-between border-b border-white/5">
              <div className="flex gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full bg-rose-500/20"></div>
                <div className="w-2.5 h-2.5 rounded-full bg-amber-500/20"></div>
                <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/20"></div>
              </div>
              <div className="text-[10px] font-mono text-slate-500 flex items-center gap-2">
                <span className="text-emerald-400/60 uppercase">{log.tool || 'bash'}</span>
                <span>—</span>
                <span>session_id: {log.id.split('-')[1]}</span>
              </div>
            </div>

            {/* Terminal Body */}
            <div className="p-4 font-mono text-[11px] leading-relaxed">
              <div className="flex gap-3 mb-3">
                <span className="text-emerald-400">root@sentinel:~$</span>
                <span className="text-slate-100">{log.toolInput}</span>
              </div>
              
              <div className="text-slate-400 whitespace-pre-wrap break-all opacity-90 border-l border-white/5 pl-4 ml-1">
                {log.toolOutput}
              </div>

              {log.action && (
                <div className="mt-4 pt-4 border-t border-white/5 flex items-center gap-2">
                  <span className="text-cyan-400 font-bold uppercase tracking-tighter text-[10px]">[RESULT]</span>
                  <span className="text-slate-200">{log.action}</span>
                </div>
              )}
            </div>
          </div>
        </div>
      ))}
      <div ref={feedEndRef} className="h-4" />
    </div>
  );
};

export default ReasoningFeed;
