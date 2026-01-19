
import React, { useState } from 'react';
import { AgentNode, AgentStatus } from '../types';
import { ICONS } from '../constants';

interface Props {
  node: AgentNode;
  level: number;
}

const AgentTreeNode: React.FC<Props> = ({ node, level }) => {
  const [isExpanded, setIsExpanded] = useState(true);

  const getStatusColor = (status: AgentStatus) => {
    switch (status) {
      case AgentStatus.RUNNING: return 'text-cyan-400 border-cyan-400 shadow-[0_0_8px_rgba(34,211,238,0.4)]';
      case AgentStatus.COMPLETED: return 'text-emerald-400 border-emerald-400';
      case AgentStatus.ERROR: return 'text-rose-400 border-rose-400';
      case AgentStatus.PAUSED: return 'text-amber-400 border-amber-400';
      default: return 'text-slate-400 border-slate-700';
    }
  };

  const getIcon = (type: string) => {
    switch (type) {
      case 'orchestrator': return <ICONS.Cpu className="w-4 h-4" />;
      case 'scanner': return <ICONS.Activity className="w-4 h-4" />;
      case 'fuzzer': return <ICONS.Zap className="w-4 h-4" />;
      case 'exploiter': return <ICONS.Shield className="w-4 h-4" />;
      default: return <ICONS.Terminal className="w-4 h-4" />;
    }
  };

  return (
    <div className="ml-4 border-l border-slate-800/50 pl-4 py-1 relative">
      <div 
        className={`flex items-start gap-3 p-3 rounded-lg border bg-slate-900/40 backdrop-blur-sm transition-all duration-300 hover:bg-slate-800/60 cursor-pointer ${getStatusColor(node.status)}`}
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <div className="mt-1">{getIcon(node.type)}</div>
        <div className="flex-1 min-w-0">
          <div className="flex justify-between items-center mb-1">
            <h4 className="text-sm font-bold truncate text-slate-200">{node.name}</h4>
            <span className="text-[10px] px-1.5 py-0.5 rounded border border-current font-mono">
              {node.status}
            </span>
          </div>
          <p className="text-[11px] text-slate-400 line-clamp-1 mono">{node.task}</p>
        </div>
      </div>

      {isExpanded && node.children && node.children.length > 0 && (
        <div className="mt-2 space-y-2">
          {node.children.map(child => (
            <AgentTreeNode key={child.id} node={child} level={level + 1} />
          ))}
        </div>
      )}
    </div>
  );
};

export default AgentTreeNode;
