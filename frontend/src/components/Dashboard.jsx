import React from 'react';
import MetricsPanel from './MetricsPanel';
import LiveFeed from './LiveFeed';

const Dashboard = ({ stats, events, onSelectEvent }) => {
  return (
    <div className="space-y-6">
      <MetricsPanel stats={stats} />
      <LiveFeed events={events} onSelectEvent={onSelectEvent} />
    </div>
  );
};

export default Dashboard;
