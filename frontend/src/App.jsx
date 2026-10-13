
import { useState } from "react";
import {
  Activity, ShieldCheck, ShieldAlert, Network, Settings,
  LayoutDashboard, ListFilter, Ban, Search, Bell
} from "lucide-react";
import {
  ResponsiveContainer, LineChart, Line, XAxis, YAxis,
  CartesianGrid, Tooltip, Legend
} from "recharts";
import "./App.css";

const demoTraffic = [
  { time: "09:50", packets: 24, benign: 20, attacks: 4, source: "172.17.0.1", destination: "172.17.0.2" },
  { time: "09:51", packets: 42, benign: 35, attacks: 7, source: "172.17.0.1", destination: "172.17.0.2" },
  { time: "09:52", packets: 18, benign: 16, attacks: 2, source: "172.18.167.99", destination: "172.17.0.2" },
  { time: "09:53", packets: 63, benign: 48, attacks: 15, source: "172.18.167.99", destination: "172.17.0.2" },
  { time: "09:54", packets: 31, benign: 28, attacks: 3, source: "172.17.0.1", destination: "172.17.0.2" },
];

const initialAlerts = [
  { time: "09:54:12", prediction: "Benign", severity: "LOW", source: "172.17.0.1", destination: "172.17.0.2", packets: 5 },
  { time: "09:53:46", prediction: "HighTraffic", severity: "HIGH", source: "172.18.167.99", destination: "172.17.0.2", packets: 200 },
  { time: "09:52:30", prediction: "PortScan", severity: "HIGH", source: "172.17.0.1", destination: "172.17.0.2", packets: 18 },
];

const navigation = [
  ["Overview", LayoutDashboard],
  ["Live Alerts", Activity],
  ["Traffic Analysis", Network],
  ["IP Management", Ban],
  ["Settings", Settings],
];

export default function App() {
  const [page, setPage] = useState("Overview");
  const [search, setSearch] = useState("");
  const [alerts, setAlerts] = useState(initialAlerts);
  const [blocked, setBlocked] = useState([]);
  const [notice, setNotice] = useState("");

  const filtered = alerts.filter((a) =>
    `${a.source} ${a.destination} ${a.prediction}`.toLowerCase().includes(search.toLowerCase())
  );

  function toggleBlock(ip) {
    if (blocked.includes(ip)) {
      setBlocked((items) => items.filter((item) => item !== ip));
      setNotice(`Removed ${ip} from the demo block list.`);
    } else {
      if (!window.confirm(`Add ${ip} to the simulated block list?`)) return;
      setBlocked((items) => [...items, ip]);
      setNotice(`${ip} added to the simulated block list. No firewall rule was changed.`);
    }
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><ShieldCheck size={28} /><div><b>SNIDS</b><small>Smart Network Intrusion Detection</small></div></div>
        <div className="nav-label">MONITORING</div>
        {navigation.map(([label, Icon]) => (
          <button key={label} className={`nav-item ${page === label ? "active" : ""}`} onClick={() => setPage(label)}>
            <Icon size={18} /> {label}
          </button>
        ))}
        <div className="sidebar-bottom"><span className="status-dot" /> Demo mode · Not live capture</div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div><small>SECURITY OPERATIONS /</small><h1>{page}</h1></div>
          <div className="top-actions"><span className="demo-tag">DEMO DATA</span><Bell size={20} /></div>
        </header>

        {notice && <div className="notice" role="status">{notice}<button onClick={() => setNotice("")}>Dismiss</button></div>}

        {page === "Overview" && <>
          <div className="metric-grid">
            <Metric icon={<Network />} label="Total flows" value="2,806" />
            <Metric icon={<ShieldCheck />} label="Benign flows" value="2,770" />
            <Metric icon={<ShieldAlert />} label="Attack alerts" value="36" danger />
            <Metric icon={<Activity />} label="Attack rate" value="1.28%" />
          </div>
          <section className="panel">
            <div className="panel-heading"><div><h2>Traffic timeline</h2><p>Hover over a point to inspect packets and endpoints</p></div><span className="live-label">● Sample series</span></div>
            <div className="chart-wrap">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={demoTraffic} margin={{ top: 12, right: 18, left: 0, bottom: 4 }}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="time" />
                  <YAxis />
                  <Tooltip content={({ active, payload, label }) => active && payload?.length ? (
                    <div className="chart-tooltip">
                      <b>{label}</b>
                      {payload.map((p) => <div key={p.dataKey}>{p.name}: {p.value} packets</div>)}
                      <hr /><div>Source: {payload[0].payload.source}</div><div>Destination: {payload[0].payload.destination}</div>
                    </div>
                  ) : null} />
                  <Legend />
                  <Line type="monotone" dataKey="benign" name="Benign packets" stroke="#0b9c76" strokeWidth={2} />
                  <Line type="monotone" dataKey="attacks" name="Attack-associated packets" stroke="#e44752" strokeWidth={2} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </section>
        </>}

        {page === "Live Alerts" && <section className="panel"><h2>Alert feed</h2><p>Sample alerts; live backend connection is not enabled yet.</p><AlertTable alerts={filtered} onBlock={toggleBlock} blocked={blocked} /></section>}
        {page === "Traffic Analysis" && <section className="panel"><h2>Traffic analysis</h2><p>Hover details are available on the overview timeline. Values currently come from sample data.</p><div className="chart-wrap"><ResponsiveContainer width="100%" height="100%"><LineChart data={demoTraffic}><CartesianGrid strokeDasharray="3 3" /><XAxis dataKey="time" /><YAxis /><Tooltip /><Line dataKey="packets" name="Packets" stroke="#377cf6" strokeWidth={2} /></LineChart></ResponsiveContainer></div></section>}
        {page === "IP Management" && <section className="panel"><h2>IP management</h2><p>Simulated block list only. No real network traffic is blocked.</p><div className="search-row"><Search size={18} /><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search IPs or predictions..." /></div><AlertTable alerts={filtered} onBlock={toggleBlock} blocked={blocked} /><h3>Simulated blocked IPs</h3>{blocked.length ? blocked.map((ip) => <div className="blocked-row" key={ip}><code>{ip}</code><button onClick={() => toggleBlock(ip)}>Unblock</button></div>) : <p>No IPs in the simulated block list.</p>}</section>}
        {page === "Settings" && <section className="panel"><h2>Settings</h2><p>These settings describe the current demo. Live detector configuration will be connected through the backend later.</p><div className="settings-row"><span>Data source</span><b>Sample data</b></div><div className="settings-row"><span>Refresh interval</span><b>Not connected</b></div><div className="settings-row"><span>Firewall enforcement</span><b>Disabled</b></div></section>}
        <footer>SNIDS · Smart Network Intrusion Detection System · Prototype interface</footer>
      </main>
    </div>
  );
}

function Metric({ icon, label, value, danger }) {
  return <div className="metric-card"><div className={`metric-icon ${danger ? "danger" : ""}`}>{icon}</div><div><strong>{value}</strong><small>{label}</small></div></div>;
}

function AlertTable({ alerts, onBlock, blocked }) {
  return <div className="table-wrap"><table><thead><tr><th>Time</th><th>Prediction</th><th>Severity</th><th>Source IP</th><th>Destination IP</th><th>Packets</th><th>Action</th></tr></thead>
    <tbody>{alerts.map((a, i) => <tr key={`${a.time}-${i}`}><td>{a.time}</td><td>{a.prediction}</td><td><span className={`severity ${a.severity.toLowerCase()}`}>{a.severity}</span></td><td><code>{a.source}</code></td><td><code>{a.destination}</code></td><td>{a.packets}</td><td><button className="small-button" onClick={() => onBlock(a.source)}>{blocked.includes(a.source) ? "Unblock (demo)" : "Block (demo)"}</button></td></tr>)}</tbody>
  </table></div>;
}

