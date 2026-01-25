import React, { useEffect, useRef, useState, useCallback } from 'react';
import { ReasoningLog } from '../types';
import { ICONS } from '../constants';

interface Props {
  logs: ReasoningLog[];
}

// Collapsed height thresholds
const INPUT_COLLAPSED_HEIGHT = 96; // 24 * 4 = 96px (max-h-24)
const OUTPUT_COLLAPSED_HEIGHT = 192; // 48 * 4 = 192px (max-h-48)
const OUTPUT_COLLAPSED_HEIGHT_SM = 256; // 64 * 4 = 256px (max-h-64 on sm+)

// Expandable content component for tool input/output
const ExpandableContent: React.FC<{
  content: string;
  type: 'input' | 'output';
  isExpanded: boolean;
  onToggle: () => void;
}> = ({ content, type, isExpanded, onToggle }) => {
  const contentRef = useRef<HTMLDivElement>(null);
  const [isOverflowing, setIsOverflowing] = useState(false);
  const [contentHeight, setContentHeight] = useState<number | null>(null);

  // Check if content overflows the collapsed height
  useEffect(() => {
    if (contentRef.current) {
      const element = contentRef.current;
      // Temporarily remove max-height to measure full content
      const originalMaxHeight = element.style.maxHeight;
      element.style.maxHeight = 'none';
      const fullHeight = element.scrollHeight;
      element.style.maxHeight = originalMaxHeight;
      
      // Compare with collapsed height threshold based on type
      const collapsedThreshold = type === 'input' ? INPUT_COLLAPSED_HEIGHT : OUTPUT_COLLAPSED_HEIGHT;
      setIsOverflowing(fullHeight > collapsedThreshold);
      setContentHeight(fullHeight);
    }
  }, [content, type]);

  if (type === 'input') {
    return (
      <div className="flex gap-2 sm:gap-3 mb-2 sm:mb-3 relative">
        <span className="text-emerald-400 flex-shrink-0">$</span>
        <div className="flex-1 min-w-0 overflow-hidden">
          <div 
            ref={contentRef}
            className={`text-slate-100 break-all whitespace-pre-wrap transition-all duration-300 ease-in-out ${
              !isExpanded ? 'max-h-24 overflow-hidden' : 'overflow-y-auto custom-scrollbar'
            }`}
            style={isExpanded ? { maxHeight: Math.min(contentHeight || 500, window.innerHeight * 0.6) } : undefined}
          >
            {content}
          </div>
          {/* Gradient overlay for collapsed state */}
          {isOverflowing && !isExpanded && (
            <div className="absolute bottom-8 left-6 right-0 h-6 bg-gradient-to-t from-[#030712] to-transparent pointer-events-none" />
          )}
          {isOverflowing && (
            <button
              onClick={(e) => { e.stopPropagation(); onToggle(); }}
              className="mt-2 flex items-center gap-1.5 text-cyan-400 hover:text-cyan-300 transition-colors text-[9px] sm:text-[10px] font-bold uppercase tracking-wider group relative z-10"
            >
              <span className={`transform transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}>
                <ICONS.ChevronDown className="w-3 h-3 sm:w-3.5 sm:h-3.5" />
              </span>
              {isExpanded ? 'Collapse Input' : 'Expand Input'}
              <span className="text-slate-600 font-normal lowercase">
                ({content.length.toLocaleString()} chars)
              </span>
            </button>
          )}
        </div>
      </div>
    );
  }

  // Output type
  return (
    <div className="relative isolate">
      <div 
        ref={contentRef}
        className={`text-slate-400 whitespace-pre-wrap break-all opacity-90 border-l border-white/5 pl-3 sm:pl-4 ml-1 custom-scrollbar transition-all duration-300 ease-in-out ${
          !isExpanded ? 'max-h-48 sm:max-h-64 overflow-hidden' : 'overflow-y-auto'
        }`}
        style={isExpanded ? { maxHeight: Math.min(contentHeight || 800, window.innerHeight * 0.7) } : undefined}
      >
        {content}
      </div>
      {/* Gradient overlay and expand button - positioned to not overlap other content */}
      {isOverflowing && (
        <div className={`relative z-10 ${
          !isExpanded 
            ? 'mt-0 pt-6 -mt-6 bg-gradient-to-t from-[#030712] via-[#030712]/90 to-transparent' 
            : 'mt-2'
        }`}>
          <button
            onClick={(e) => { e.stopPropagation(); onToggle(); }}
            className="flex items-center gap-1.5 text-cyan-400 hover:text-cyan-300 transition-colors text-[9px] sm:text-[10px] font-bold uppercase tracking-wider group ml-4"
          >
            <span className={`transform transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}>
              <ICONS.ChevronDown className="w-3 h-3 sm:w-3.5 sm:h-3.5" />
            </span>
            {isExpanded ? 'Collapse Output' : 'Expand Output'}
            <span className="text-slate-600 font-normal lowercase">
              ({content.length.toLocaleString()} chars)
            </span>
          </button>
        </div>
      )}
    </div>
  );
};

// Individual log entry component with expand/collapse state
const LogEntry: React.FC<{
  log: ReasoningLog;
  index: number;
  getSeverityGlow: (severity?: string) => string;
  getSeverityDotColor: (severity?: string) => string;
  getSeverityBadgeStyle: (severity?: string) => string;
}> = ({ log, index, getSeverityGlow, getSeverityDotColor, getSeverityBadgeStyle }) => {
  const [inputExpanded, setInputExpanded] = useState(false);
  const [outputExpanded, setOutputExpanded] = useState(false);

  // Reset expansion states when log changes (for recycled components)
  useEffect(() => {
    setInputExpanded(false);
    setOutputExpanded(false);
  }, [log.id]);

  return (
    <div 
      key={log.id || `log-${index}`} 
      className="flex flex-col gap-2 sm:gap-3 group animate-in fade-in slide-in-from-bottom-4 duration-500 isolate"
      style={{ animationDelay: `${Math.min(index * 50, 500)}ms` }}
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
        <div className={`ml-4 sm:ml-6 rounded-lg border bg-[#030712] ${getSeverityGlow(log.severity)} relative isolate`}>
          {/* Terminal Header */}
          <div className="bg-slate-900/80 px-3 sm:px-4 py-2 flex items-center justify-between border-b border-white/5 sticky top-0 z-20">
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

          {/* Terminal Body - contains expandable content blocks */}
          <div className="p-3 sm:p-4 font-mono text-[10px] sm:text-[11px] leading-relaxed space-y-3">
            {log.toolInput && (
              <div className="relative">
                <ExpandableContent 
                  content={log.toolInput}
                  type="input"
                  isExpanded={inputExpanded}
                  onToggle={() => setInputExpanded(!inputExpanded)}
                />
              </div>
            )}
            
            {log.toolOutput && (
              <div className="relative">
                <ExpandableContent 
                  content={log.toolOutput}
                  type="output"
                  isExpanded={outputExpanded}
                  onToggle={() => setOutputExpanded(!outputExpanded)}
                />
              </div>
            )}

            {log.action && (
              <div className="mt-3 sm:mt-4 pt-3 sm:pt-4 border-t border-white/5 flex flex-wrap items-center gap-2 relative z-10">
                <span className="text-cyan-400 font-bold uppercase tracking-tighter text-[9px] sm:text-[10px]">[RESULT]</span>
                <span className="text-slate-200 text-[10px] sm:text-[11px]">{log.action}</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

// Maximum number of logs to render for performance
const MAX_VISIBLE_LOGS = 65;

const ReasoningFeed: React.FC<Props> = ({ logs }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const feedEndRef = useRef<HTMLDivElement>(null);
  const [isUserNearBottom, setIsUserNearBottom] = useState(true);
  const [showScrollToBottom, setShowScrollToBottom] = useState(false);
  const isAutoScrollingRef = useRef(false);
  const lastLogCountRef = useRef(0);
  
  // Performance optimization: Only render the most recent logs to prevent lag
  // When logs exceed MAX_VISIBLE_LOGS, older logs are trimmed from display
  const visibleLogs = logs.length > MAX_VISIBLE_LOGS 
    ? logs.slice(-MAX_VISIBLE_LOGS) 
    : logs;
  const trimmedCount = logs.length > MAX_VISIBLE_LOGS 
    ? logs.length - MAX_VISIBLE_LOGS 
    : 0;

  // Check if user is near bottom of the feed
  const checkIfNearBottom = useCallback(() => {
    if (!containerRef.current) return true;
    const container = containerRef.current;
    const threshold = 150; // pixels from bottom to consider "near bottom"
    const distanceFromBottom = container.scrollHeight - container.scrollTop - container.clientHeight;
    return distanceFromBottom <= threshold;
  }, []);

  // Handle scroll events to track user position
  const handleScroll = useCallback(() => {
    // Ignore scroll events triggered by auto-scroll
    if (isAutoScrollingRef.current) return;
    
    const nearBottom = checkIfNearBottom();
    setIsUserNearBottom(nearBottom);
    setShowScrollToBottom(!nearBottom && logs.length > 0);
  }, [checkIfNearBottom, logs.length]);

  // Auto-scroll to bottom only if user is near bottom
  useEffect(() => {
    // Only auto-scroll if new logs were added and user is near bottom
    if (visibleLogs.length > 0 && logs.length > lastLogCountRef.current && isUserNearBottom && feedEndRef.current) {
      isAutoScrollingRef.current = true;
      feedEndRef.current.scrollIntoView({ behavior: 'smooth' });
      
      // Reset auto-scrolling flag after animation completes
      setTimeout(() => {
        isAutoScrollingRef.current = false;
      }, 500);
    }
    lastLogCountRef.current = logs.length;
  }, [logs, visibleLogs.length, isUserNearBottom]);

  // Add scroll event listener
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    container.addEventListener('scroll', handleScroll, { passive: true });
    return () => container.removeEventListener('scroll', handleScroll);
  }, [handleScroll]);

  // Scroll to bottom button handler
  const scrollToBottom = useCallback(() => {
    if (feedEndRef.current) {
      isAutoScrollingRef.current = true;
      feedEndRef.current.scrollIntoView({ behavior: 'smooth' });
      setIsUserNearBottom(true);
      setShowScrollToBottom(false);
      
      setTimeout(() => {
        isAutoScrollingRef.current = false;
      }, 500);
    }
  }, []);

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
    <div 
      ref={containerRef}
      className="flex-1 overflow-y-auto px-3 sm:px-4 py-4 sm:py-6 space-y-4 sm:space-y-6 scroll-smooth custom-scrollbar relative"
    >
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
      
      {/* Show indicator when older logs have been trimmed for performance */}
      {trimmedCount > 0 && (
        <div className="text-center py-2 px-4 bg-slate-800/30 rounded-lg border border-slate-700/50 mb-4">
          <p className="text-[9px] sm:text-[10px] text-slate-500 font-mono">
            <span className="text-cyan-500">{trimmedCount}</span> older events hidden for performance
            <span className="text-slate-600 ml-2">• Showing latest {MAX_VISIBLE_LOGS}</span>
          </p>
        </div>
      )}
      
      {visibleLogs.map((log, index) => (
        <LogEntry
          key={log.id || `log-${index}`}
          log={log}
          index={index}
          getSeverityGlow={getSeverityGlow}
          getSeverityDotColor={getSeverityDotColor}
          getSeverityBadgeStyle={getSeverityBadgeStyle}
        />
      ))}
      
      <div ref={feedEndRef} className="h-4" />

      {/* Scroll to bottom button - appears when user scrolls away from bottom */}
      {showScrollToBottom && (
        <button
          onClick={scrollToBottom}
          className="fixed bottom-20 lg:bottom-16 right-4 lg:right-auto lg:left-1/2 lg:-translate-x-1/2 z-20 flex items-center gap-2 px-4 py-2 bg-cyan-500/90 hover:bg-cyan-400 text-slate-950 rounded-full shadow-lg shadow-cyan-500/30 transition-all duration-200 hover:scale-105 animate-in fade-in slide-in-from-bottom-4"
        >
          <ICONS.ChevronDown className="w-4 h-4 animate-bounce" />
          <span className="text-[10px] sm:text-xs font-bold uppercase tracking-wider">
            New Activity
          </span>
          <span className="text-[9px] sm:text-[10px] bg-slate-950/30 px-1.5 py-0.5 rounded">
            {visibleLogs.length}{trimmedCount > 0 ? `/${logs.length}` : ''}
          </span>
        </button>
      )}
    </div>
  );
};

export default ReasoningFeed;
