import React from 'react';

const getSeverityStyle = (severity) => {
  switch (severity) {
    case 'Critical':
      return 'bg-red-50 text-red-700 border border-red-200';
    case 'High':
      return 'bg-orange-50 text-orange-700 border border-orange-200';
    case 'Medium':
      return 'bg-amber-50 text-amber-700 border border-amber-200';
    default:
      return 'bg-emerald-50 text-emerald-700 border border-emerald-200';
  }
};

const getSourceIcon = (source) => {
  if (source === 'Network') {
    return (
      <svg className="w-4 h-4 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
      </svg>
    );
  }
  return (
    <svg className="w-4 h-4 text-violet-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
    </svg>
  );
};

const LiveFeed = ({ events, onSelectEvent }) => {
  return (
    <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
      {/* Header */}
      <div className="px-5 py-4 border-b border-slate-100 flex justify-between items-center">
        <div>
          <h3 className="text-sm font-semibold text-slate-900">Live Event Feed</h3>
          <p className="text-xs text-slate-500 mt-0.5">{events.length} events in buffer</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="relative flex h-2.5 w-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
          </span>
          <span className="text-xs text-slate-500">Live</span>
        </div>
      </div>

      {/* Event List */}
      <div className="divide-y divide-slate-100 max-h-[480px] overflow-y-auto">
        {events.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-slate-400">
            <svg className="w-12 h-12 mb-3 text-slate-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
            </svg>
            <p className="text-sm">Waiting for incoming events...</p>
          </div>
        ) : (
          events.map((event) => (
            <div 
              key={event.id} 
              onClick={() => onSelectEvent(event)}
              className="px-5 py-3.5 hover:bg-slate-50 cursor-pointer transition-colors"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-start gap-3 min-w-0">
                  <div className="mt-0.5">
                    {getSourceIcon(event.source)}
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-sm font-medium text-slate-900 truncate">
                        {event.attack_type}
                      </span>
                      <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${getSeverityStyle(event.severity)}`}>
                        {event.severity}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 text-xs text-slate-500">
                      <span>{event.source}</span>
                      <span className="text-slate-300">|</span>
                      <span>{event.host}</span>
                      <span className="text-slate-300">|</span>
                      <span>{(event.confidence * 100).toFixed(1)}%</span>
                    </div>
                  </div>
                </div>
                <div className="text-right shrink-0">
                  <p className="text-xs text-slate-400">
                    {new Date(event.timestamp).toLocaleTimeString()}
                  </p>
                  <p className="text-[10px] text-slate-400 mt-0.5">#{event.id}</p>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default LiveFeed;
