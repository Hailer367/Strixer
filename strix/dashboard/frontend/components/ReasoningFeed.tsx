import React, { useEffect, useRef } from 'react';
import { ReasoningLog } from '../types';
import { ICONS } from '../constants';

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
      case 'critical': return 'shadow-[0_0_20px_rgba(244,63,94,0.2)] border-rose-500/40';
      case 'high': return 'shadow-[0_0_20px_rgba(249,115,22,0.2)] border-orange-500/40';
      case 'medium': return 'shadow-[0_0_15px_rgba(245,158,11,0.15)] border-amber-500/40';
      case 'low': return 'shadow-[0_0_10px_rgba(34,211,238,0.1)] border-cyan-500/30';
      default: return 'border-slate-800/50';
    }
  };

  const getSeverityDotColor = (severity?: string) => {
    switch (severity) {
      case 'critical': return 'bg-rose-500 animate-pulse shadow-[0_0_8px_#f43f5e]';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-amber-500';
      case 'low': return 'bg-cyan-500';
      default: return 'bg-slate-500';
    }
  };

  const getSeverityBadgeStyle = (severity?: string) => {
    switch (severity) {
      case 'critical': return 'border-rose-500/50 text-rose-400 bg-rose-500/10';
      case 'high': return 'border-orange-500/50 text-orange-400 bg-orange-500/10';
      case 'medium': return 'border-amber-500/50 text-amber-400 bg-amber-500/10';
      case 'low': return 'border-cyan-500/50 text-cyan-400 bg-cyan-500/10';
      default: return 'border-slate-700 text-slate-400 bg-slate-800/40';
    }
  };

  return (
    <div className="flex-1 overflow-y-auto px-3 sm:px-4 py-4 sm:py-6 space-y-4 sm:space-y-6 scroll-smooth custom-scrollbar">
      {logs.length === 0 && (
        <div className="flex flex-col items-center justify-center h-full text-slate-500 space-y-4 py-20">
          <div className="relative">
            <div className="w-12 h-12 sm:w-16 sm:h-16 rounded-full border-2 border-slate-700 border-t-cyan-500 animate-spin" />
            <div className="absolute inset-0 flex items-center justify-center">
              <ICONS.Terminal className="w-5 h-5 sm:w-6 sm:h-6 text-cyan-500/50" />
            </div>
          </div>
          <div className="text-center space-y-2">
            <p className="animate-pulse font-mono uppercase tracking-widest text-[9px] sm:text-[10px]">
              Initializing Neural Context...
            </p>
            <p className="text-[8px] sm:text-[9px] text-slate-600 max-w-xs">
              Waiting for agent activity. Events will appear here in real-time.
            </p>
          </div>
        </div>
      )}
      
      {logs.map((log, index) => (
        <div 
          key={log.id || `log-${index}`} 
          className="flex flex-col gap-2 sm:gap-3 group animate-in fade-in slide-in-from-bottom-4 duration-500"
          style={{ animationDelay: `${index * 50}ms` }}
        >
          {/* Header & Thought */}
          <div className="flex gap-2 sm:gap-4 items-start">
            <div className="flex-shrink-0 mt-1.5">
              <div className={`w-2 h-2 rounded-full ${getSeverityDotColor(log.severity)}`} />
            </div>
            <div className="flex-1 space-y-1.5 sm:space-y-2 min-w-0">
              {/* Header row */}
              <div className="flex flex-wrap items-center gap-2 sm:gap-3">
                <span className="text-[9px] sm:text-[10px] font-mono text-slate-500">[{log.timestamp}]</span>
                <span className="text-[8px] sm:text-[10px] font-bold uppercase tracking-widest text-cyan-500/80">
                  REASONING_ENGINE
                </span>
                <span className="hidden sm:block h-[1px] flex-1 bg-slate-800/50" />
                <span className={`text-[8px] sm:text-[9px] px-1.5 py-0.5 rounded border font-bold uppercase ${getSeverityBadgeStyle(log.severity)}`}>
                  {log.severity || 'info'}
                </span>
              </div>
              
              {/* Thought content */}
              {log.thought && (
                <p className="text-xs sm:text-sm text-slate-300 leading-relaxed italic border-l-2 border-slate-700 pl-3 sm:pl-4 py-1 bg-slate-900/30 rounded-r-lg">
                  {log.thought}
                </p>
              )}
            </div>
          </div>

          {/* Terminal Block */}
          {(log.toolInput || log.toolOutput) && (
            <div className={`ml-4 sm:ml-6 rounded-lg overflow-hidden border bg-[#030712] ${getSeverityGlow(log.severity)}`}>
              {/* Terminal Header */}
              <div className="bg-slate-900/80 px-3 sm:px-4 py-2 flex items-center justify-between border-b border-white/5">
                <div className="flex gap-1.5">
                  <div className="w-2 h-2 sm:w-2.5 sm:h-2.5 rounded-full bg-rose-500/30" />
                  <div className="w-2 h-2 sm:w-2.5 sm:h-2.5 rounded-full bg-amber-500/30" />
                  <div className="w-2 h-2 sm:w-2.5 sm:h-2.5 rounded-full bg-emerald-500/30" />
                </div>
                <div className="text-[8px] sm:text-[10px] font-mono text-slate-500 flex items-center gap-1.5 sm:gap-2 truncate ml-2">
                  <span className="text-emerald-400/60 uppercase truncate max-w-[80px] sm:max-w-none">
                    {log.tool || 'terminal'}
                  </span>
                  <span className="hidden sm:inline">—</span>
                  <span className="hidden sm:inline text-slate-600">
                    session_id: {log.id?.split('-')[1] || '0'}
                  </span>
                </div>
              </div>

              {/* Terminal Body */}
              <div className="p-3 sm:p-4 font-mono text-[10px] sm:text-[11px] leading-relaxed overflow-x-auto">
                {log.toolInput && (
                  <div className="flex gap-2 sm:gap-3 mb-2 sm:mb-3">
                    <span className="text-emerald-400 flex-shrink-0">$</span>
                    <span className="text-slate-100 break-all">{log.toolInput}</span>
                  </div>
                )}
                
                {log.toolOutput && (
                  <div className="text-slate-400 whitespace-pre-wrap break-all opacity-90 border-l border-white/5 pl-3 sm:pl-4 ml-1 max-h-48 sm:max-h-64 overflow-y-auto custom-scrollbar">
                    {log.toolOutput}
                  </div>
                )}

                {log.action && (
                  <div className="mt-3 sm:mt-4 pt-3 sm:pt-4 border-t border-white/5 flex flex-wrap items-center gap-2">
                    <span className="text-cyan-400 font-bold uppercase tracking-tighter text-[9px] sm:text-[10px]">[RESULT]</span>
                    <span className="text-slate-200 text-[10px] sm:text-[11px]">{log.action}</span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      ))}
      
      <div ref={feedEndRef} className="h-4" />
    </div>
  );
};

export default ReasoningFeed;
