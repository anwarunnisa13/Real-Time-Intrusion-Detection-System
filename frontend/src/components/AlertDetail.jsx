import React from 'react';

const getSeverityStyle = (severity) => {
  switch (severity) {
    case 'Critical':
      return 'bg-red-500';
    case 'High':
      return 'bg-orange-500';
    case 'Medium':
      return 'bg-amber-500';
    default:
      return 'bg-emerald-500';
  }
};

const AlertDetail = ({ event, onBack }) => {
  if (!event) return null;

  return (
    <div className="space-y-6">
      {/* Back Button */}
      <button 
        onClick={onBack}
        className="inline-flex items-center gap-2 text-sm font-medium text-slate-600 hover:text-slate-900 transition-colors"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
        </svg>
        Back to Dashboard
      </button>

      {/* Header Card */}
      <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6">
        <div className="flex flex-wrap justify-between items-start gap-4">
          <div className="flex items-start gap-4">
            <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${getSeverityStyle(event.severity)}`}>
              <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <div>
              <h2 className="text-xl font-semibold text-slate-900">{event.attack_type}</h2>
              <p className="text-sm text-slate-500 mt-0.5">
                Event #{event.id} &bull; {event.source} Detection
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className={`px-3 py-1.5 rounded-lg text-sm font-medium text-white ${getSeverityStyle(event.severity)}`}>
              {event.severity}
            </span>
            <span className="text-sm text-slate-500">
              {new Date(event.timestamp).toLocaleString()}
            </span>
          </div>
        </div>
      </div>

      {/* Details Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Detection Info */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6">
          <div className="flex items-center gap-2 mb-4">
            <div className="w-8 h-8 bg-blue-50 rounded-lg flex items-center justify-center">
              <svg className="w-4 h-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <h3 className="text-sm font-semibold text-slate-900">Detection Details</h3>
          </div>
          
          <div className="space-y-3">
            <div className="flex justify-between py-2 border-b border-slate-100">
              <span className="text-sm text-slate-500">Target Host / IP</span>
              <span className="text-sm font-medium text-slate-900 font-mono">{event.host}</span>
            </div>
            <div className="flex justify-between py-2 border-b border-slate-100">
              <span className="text-sm text-slate-500">Confidence Score</span>
              <span className="text-sm font-medium text-blue-600">{(event.confidence * 100).toFixed(2)}%</span>
            </div>
            <div className="flex justify-between py-2 border-b border-slate-100">
              <span className="text-sm text-slate-500">Detection Model</span>
              <span className="text-sm font-medium text-slate-900">
                {event.source === 'Network' ? 'MLP Classifier' : 'CNN-LSTM Model'}
              </span>
            </div>
            {event.true_label && (
              <div className="flex justify-between py-2">
                <span className="text-sm text-slate-500">Ground Truth</span>
                <span className="text-sm font-medium text-slate-900">{event.true_label}</span>
              </div>
            )}
          </div>
        </div>

        {/* XAI Section */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6">
          <div className="flex items-center gap-2 mb-4">
            <div className="w-8 h-8 bg-violet-50 rounded-lg flex items-center justify-center">
              <svg className="w-4 h-4 text-violet-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
              </svg>
            </div>
            <h3 className="text-sm font-semibold text-slate-900">Explainable AI (XAI)</h3>
          </div>
          
          <div className="space-y-4">
            {/* SHAP Values */}
            {event.explanation.shap && (
              <div>
                <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
                  SHAP Feature Impact
                </h4>
                <div className="space-y-2">
                  {Object.entries(event.explanation.shap).filter(([k]) => k !== 'Note').map(([feature, value]) => (
                    <div key={feature} className="flex items-center gap-3">
                      <div className="w-1/3 text-xs text-slate-600 truncate" title={feature}>
                        {feature.length > 20 ? feature.substring(0, 20) + '...' : feature}
                      </div>
                      <div className="flex-1 h-5 bg-slate-100 rounded-full overflow-hidden relative">
                        <div 
                          className={`absolute h-full rounded-full ${value > 0 ? 'bg-blue-500' : 'bg-rose-400'}`}
                          style={{ 
                            width: `${Math.min(Math.abs(value) * 100, 100)}%`,
                            left: value < 0 ? `${100 - Math.min(Math.abs(value) * 100, 100)}%` : '0'
                          }}
                        />
                      </div>
                      <div className="w-16 text-right text-xs font-mono text-slate-600">
                        {value > 0 ? '+' : ''}{typeof value === 'number' ? value.toFixed(4) : value}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* LIME Explanation */}
            {event.explanation.lime && (
              <div>
                <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">
                  LIME Explanation
                </h4>
                <div className="bg-slate-50 rounded-lg p-3 border border-slate-100">
                  <p className="text-sm text-slate-700">{event.explanation.lime}</p>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Related Incidents */}
        <div className="lg:col-span-2 bg-white rounded-xl border border-slate-200 shadow-sm p-6">
          <div className="flex items-center gap-2 mb-4">
            <div className="w-8 h-8 bg-amber-50 rounded-lg flex items-center justify-center">
              <svg className="w-4 h-4 text-amber-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <h3 className="text-sm font-semibold text-slate-900">Historical Incident Correlation</h3>
          </div>
          
          <div className="bg-slate-50 rounded-lg p-4 border border-slate-100 text-center">
            <p className="text-sm text-slate-500 italic">
              Retrieving similar past events via KNN/HNSW vector search...
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AlertDetail;
