import React, { useState, useEffect } from 'react';
import io from 'socket.io-client';
import Dashboard from './components/Dashboard';
import AlertDetail from './components/AlertDetail';

const SOCKET_URL = 'http://localhost:8000';

function App() {
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState({
    total_events: 0,
    attacks_detected: 0,
    normal_events: 0,
    attack_types: {},
    mode: 'csv'
  });
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [mode, setMode] = useState('csv');
  const [socket, setSocket] = useState(null);

  useEffect(() => {
    const s = io(SOCKET_URL);
    setSocket(s);

    s.on('connect', () => setIsConnected(true));
    s.on('disconnect', () => setIsConnected(false));
    s.on('new_event', (event) => {
      setEvents((prev) => [event, ...prev].slice(0, 100));
    });
    s.on('stats_update', (newStats) => setStats(newStats));
    s.on('mode_changed', (data) => setMode(data.mode));

    return () => s.disconnect();
  }, []);

  const switchMode = (newMode) => {
    if (socket) {
      socket.emit('switch_mode', { mode: newMode });
    }
  };

  return (
    <div className="min-h-screen bg-slate-50">
      {/* Header */}
      <header className="bg-white border-b border-slate-200 shadow-sm">
        <div className="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
              <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <div>
              <h1 className="text-xl font-semibold text-slate-900">Hybrid IDS Dashboard</h1>
              <p className="text-xs text-slate-500">Explainable AI-Based Intrusion Detection System</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            {/* Mode Switcher */}
            <div className="flex items-center bg-slate-100 rounded-lg p-1">
              <button
                onClick={() => switchMode('csv')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all ${
                  mode === 'csv'
                    ? 'bg-white text-slate-900 shadow-sm'
                    : 'text-slate-500 hover:text-slate-700'
                }`}
              >
                CSV Data
              </button>
              <button
                onClick={() => switchMode('live')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all ${
                  mode === 'live'
                    ? 'bg-emerald-600 text-white shadow-sm'
                    : 'text-slate-500 hover:text-slate-700'
                }`}
              >
                Live Monitor
              </button>
            </div>
            <div className="text-right">
              <p className="text-xs text-slate-500">Status</p>
              <p className={`text-sm font-medium ${isConnected ? 'text-emerald-600' : 'text-red-500'}`}>
                {isConnected ? 'Connected' : 'Disconnected'}
              </p>
            </div>
            <div className={`w-2.5 h-2.5 rounded-full ${isConnected ? 'bg-emerald-500' : 'bg-red-500'}`}></div>
          </div>
        </div>
      </header>

      {/* Mode Banner */}
      {mode === 'live' && (
        <div className="bg-emerald-50 border-b border-emerald-200">
          <div className="max-w-7xl mx-auto px-6 py-2 flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <p className="text-sm text-emerald-700 font-medium">
              Live Monitoring Active - Capturing real network traffic and system logs
            </p>
          </div>
        </div>
      )}

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-6 py-6">
        {selectedEvent ? (
          <AlertDetail event={selectedEvent} onBack={() => setSelectedEvent(null)} />
        ) : (
          <Dashboard 
            stats={stats} 
            events={events} 
            onSelectEvent={setSelectedEvent} 
          />
        )}
      </main>
    </div>
  );
}

export default App;
