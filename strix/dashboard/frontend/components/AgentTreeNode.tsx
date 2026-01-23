import React, { useState } from 'react';
import { AgentNode, AgentStatus, AgentInfo } from '../types';
import { ICONS } from '../constants';

interface Props {
  node: AgentNode | AgentInfo;
  level: number;
}

const AgentTreeNode: React.FC<Props> = ({ node, level }) => {
  const [isExpanded, setIsExpanded] = useState(true);

  // Normalize status - handle both uppercase enum and lowercase string from API
  const normalizeStatus = (status: string | AgentStatus): string => {
    if (typeof status === 'string') {
      return status.toUpperCase();
    }
    return status;
  };

  const getStatusStyles = (status: AgentStatus | string) => {
    const normalizedStatus = normalizeStatus(status);
    switch (normalizedStatus) {
      case 'RUNNING':
      case 'ACTIVE':
        return 'border-cyan-500/30 bg-cyan-500/5 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.1)]';
      case 'COMPLETED':
      case 'DONE':
        return 'border-emerald-500/30 bg-emerald-500/5 text-emerald-400';
      case 'ERROR':
      case 'FAILED':
        return 'border-rose-500/30 bg-rose-500/5 text-rose-400';
      case 'PAUSED':
      case 'WAITING':
        return 'border-amber-500/30 bg-amber-500/5 text-amber-400';
      case 'IDLE':
      default:
        return 'border-slate-800 bg-slate-900/40 text-slate-400';
    }
  };

  const getStatusDot = (status: AgentStatus | string) => {
    const normalizedStatus = normalizeStatus(status);
    switch (normalizedStatus) {
      case 'RUNNING':
      case 'ACTIVE':
        return 'bg-cyan-500 animate-pulse shadow-[0_0_8px_#06b6d4]';
      case 'COMPLETED':
      case 'DONE':
        return 'bg-emerald-500';
      case 'ERROR':
      case 'FAILED':
        return 'bg-rose-500 animate-pulse';
      case 'PAUSED':
      case 'WAITING':
        return 'bg-amber-500';
      default:
        return 'bg-slate-500';
    }
  };

  const getIcon = (type: string) => {
    const normalizedType = type?.toLowerCase() || '';
    switch (normalizedType) {
      case 'orchestrator':
      case 'coordinator':
        return <ICONS.Cpu className="w-4 h-4 text-purple-400" />;
      case 'scanner':
      case 'recon':
        return <ICONS.Activity className="w-4 h-4 text-cyan-400" />;
      case 'fuzzer':
      case 'tester':
        return <ICONS.Zap className="w-4 h-4 text-amber-400" />;
      case 'exploiter':
      case 'attacker':
        return <ICONS.Shield className="w-4 h-4 text-rose-400" />;
      case 'reporter':
      case 'analyzer':
        return <ICONS.Database className="w-4 h-4 text-emerald-400" />;
      default:
        return <ICONS.Terminal className="w-4 h-4 text-slate-400" />;
    }
  };

  // Get task text - handle both old and new API formats
  const getTaskText = (): string => {
    const agentNode = node as AgentNode;
    const agentInfo = node as AgentInfo;
    return agentInfo.current_task || agentNode.task || 'Initializing...';
  };

  // Get children - handle both formats
  const getChildren = (): (AgentNode | AgentInfo)[] => {
    const agentNode = node as AgentNode;
    return agentNode.children || [];
  };

  // Get tool count if available
  const getToolCount = (): number | undefined => {
    const agentInfo = node as AgentInfo;
    return agentInfo.tool_count;
  };

  const children = getChildren();
  const hasChildren = children.length > 0;
  const toolCount = getToolCount();

  return (
    <div className={`relative ${level > 0 ? 'ml-4 sm:ml-6 mt-2 sm:mt-3 border-l-2 border-slate-800/30 pl-3 sm:pl-4' : ''}`}>
      <div
        className={`group flex items-center gap-2 sm:gap-4 p-3 sm:p-4 rounded-xl sm:rounded-2xl border backdrop-blur-md transition-all duration-500 hover:scale-[1.01] active:scale-[0.99] cursor-pointer ${getStatusStyles(node.status)}`}
        onClick={() => hasChildren && setIsExpanded(!isExpanded)}
      >
        {/* Icon */}
        <div className={`p-1.5 sm:p-2 rounded-lg sm:rounded-xl bg-slate-950/50 border border-white/5 transition-transform group-hover:rotate-12 flex-shrink-0`}>
          {getIcon(node.type)}
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex justify-between items-center gap-2 mb-1">
            <h4 className="text-[10px] sm:text-xs font-black uppercase tracking-tighter truncate text-slate-100">{node.name}</h4>
            <div className="flex items-center gap-2 flex-shrink-0">
              {toolCount !== undefined && toolCount > 0 && (
                <span className="text-[8px] sm:text-[9px] px-1.5 py-0.5 bg-slate-800/50 rounded text-slate-400 font-mono flex items-center gap-1">
                  <ICONS.Tool className="w-2.5 h-2.5" />
                  {toolCount}
                </span>
              )}
              <span className={`flex h-2 w-2 rounded-full ${getStatusDot(node.status)}`}></span>
            </div>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[8px] sm:text-[9px] font-mono opacity-50 uppercase tracking-widest">{normalizeStatus(node.status)}</span>
            <span className="w-1 h-1 rounded-full bg-slate-700 hidden sm:block"></span>
            <p className="text-[9px] sm:text-[10px] text-slate-500 truncate group-hover:text-slate-400 transition-colors font-mono max-w-full sm:max-w-none">
              {getTaskText()}
            </p>
          </div>
        </div>

        {/* Expand/Collapse Arrow */}
        {hasChildren && (
          <div className={`transition-transform duration-300 flex-shrink-0 ${isExpanded ? 'rotate-180' : ''}`}>
            <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" className="opacity-30"><path d="m6 9 6 6 6-6" /></svg>
          </div>
        )}
      </div>

      {/* Children */}
      {isExpanded && hasChildren && (
        <div className="animate-in slide-in-from-top-2 fade-in duration-500">
          {children.map((child) => (
            <AgentTreeNode key={child.id} node={child} level={level + 1} />
          ))}
        </div>
      )}
    </div>
  );
};

export default AgentTreeNode;
