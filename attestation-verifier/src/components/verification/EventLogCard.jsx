import { Card } from '../ui/Card.jsx';

export function EventLogCard({ eventCount }) {
  return (
    <Card title="Event log">
      <div className="event-count">{eventCount} events in event log</div>
    </Card>
  );
}
