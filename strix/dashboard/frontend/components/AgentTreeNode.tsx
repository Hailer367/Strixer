import React, { useState } from 'react';
import { AgentNode, AgentStatus } from '../types';
import { ICONS } from '../constants';

interface Props {
  node: AgentNode;
  level: number;
}

const AgentTreeNode: React.FC<Props> = ({ node, level }) => {
  const [isExpanded, setIsExpanded] = useState(true);

  const getStatusStyles = (status: AgentStatus | string) => {
    switch (status) {
      case 'RUNNING':
      case AgentStatus.RUNNING:
        return 'border-cyan-500/30 bg-cyan-500/5 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.1)]';
      case 'COMPLETED':
      case AgentStatus.COMPLETED:
        return 'border-emerald-500/30 bg-emerald-500/5 text-emerald-400';
      case 'ERROR':
      case AgentStatus.ERROR:
        return 'border-rose-500/30 bg-rose-500/5 text-rose-400';
      default:
        return 'border-slate-800 bg-slate-900/40 text-slate-400';
    }
  };

  const getIcon = (type: string) => {
    switch (type) {
      case 'orchestrator': return <ICONS.Cpu className="w-4 h-4 text-purple-400" />;
      case 'scanner': return <ICONS.Activity className="w-4 h-4 text-cyan-400" />;
      case 'fuzzer': return <ICONS.Zap className="w-4 h-4 text-amber-400" />;
      case 'exploiter': return <ICONS.Shield className="w-4 h-4 text-rose-400" />;
      default: return <ICONS.Terminal className="w-4 h-4 text-slate-400" />;
    }
  };

  return (
    <div className={`relative ${level > 0 ? 'ml-6 mt-3 border-l-2 border-slate-800/30 pl-4' : ''}`}>
      <div
        className={`group flex items-center gap-4 p-4 rounded-2xl border backdrop-blur-md transition-all duration-500 hover:scale-[1.02] active:scale-[0.98] cursor-pointer ${getStatusStyles(node.status)}`}
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <div className={`p-2 rounded-xl bg-slate-950/50 border border-white/5 transition-transform group-hover:rotate-12`}>
          {getIcon(node.type)}
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex justify-between items-center mb-1">
            <h4 className="text-xs font-black uppercase tracking-tighter truncate text-slate-100">{node.name}</h4>
            {(node.status === 'RUNNING' || node.status === AgentStatus.RUNNING) && (
              <span className="flex h-2 w-2 rounded-full bg-cyan-500 animate-pulse shadow-[0_0_8px_#06b6d4]"></span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[9px] font-mono opacity-50 uppercase tracking-widest">{node.status}</span>
            <span className="w-1 h-1 rounded-full bg-slate-700"></span>
            <p className="text-[10px] text-slate-500 truncate group-hover:text-slate-400 transition-colors uppercase font-mono">{node.current_task || node.task}</p>
          </div>
        </div>

        {node.children && node.children.length > 0 && (
          <div className={`transition-transform duration-300 ${isExpanded ? 'rotate-180' : ''}`}>
            <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" className="opacity-30"><path d="m6 9 6 6 6-6" /></svg>
          </div>
        )}
      </div>

      {isExpanded && node.children && node.children.length > 0 && (
        <div className="animate-in slide-in-from-top-2 fade-in duration-500">
          {node.children.map(child => (
            <AgentTreeNode key={child.id} node={child} level={level + 1} />
          ))}
        </div>
      )}
    </div>
  );
};

export default AgentTreeNode;
