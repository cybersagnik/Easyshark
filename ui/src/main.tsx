import { StrictMode, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

type Session = { key: string; pcap_path: string; last_active: string };
type EventMessage = { event: string; ts: number; payload: Record<string, unknown> };
type Graph = { nodes?: Array<Record<string, unknown>>; edges?: Array<Record<string, string>> };
type Packet = { index: number; timestamp: number; protocol?: string; src_ip?: string; dst_ip?: string; src_port?: number; dst_port?: number; length?: number; payload_hex?: string };
type Alert = { session?: string; event?: string; payload?: Record<string, unknown>; acknowledged?: boolean };
type Report = { file: string; timestamp?: string; conclusion?: Record<string, unknown> };

const pretty = (value: unknown) => String(value ?? "—");
const eventLabel = (value: string) => value.replaceAll("_", " ");

function Icon({ children }: { children: string }) { return <span className="icon" aria-hidden="true">{children}</span>; }

function GraphView({ graph, zoom, setZoom }: { graph: Graph; zoom: number; setZoom: (value: number) => void }) {
  const nodes = graph.nodes ?? [];
  const positions = nodes.slice(0, 24).map((node, index) => ({ node, x: 9 + (index % 6) * 16, y: 15 + Math.floor(index / 6) * 25 }));
  const byId = new Map(positions.map(item => [String(item.node.id), item]));
  return <div className="graph-wrap"><div className="graph-toolbar"><span><i className="legend-dot cyan"/> evidence <i className="legend-dot purple"/> claim <i className="legend-dot orange"/> alert</span><div><button className="mini" onClick={() => setZoom(Math.min(1.4, zoom + .1))}>＋</button><b>{Math.round(zoom * 100)}%</b><button className="mini" onClick={() => setZoom(Math.max(.7, zoom - .1))}>−</button></div></div>
    <div className="graph" style={{ transform: `scale(${zoom})` }} aria-label="Interactive evidence graph"><svg viewBox="0 0 100 100" preserveAspectRatio="none">{(graph.edges ?? []).map((edge, index) => { const from = byId.get(pretty(edge.source)); const to = byId.get(pretty(edge.target)); return from && to ? <line key={index} x1={from.x + 4} y1={from.y + 4} x2={to.x + 4} y2={to.y + 4} /> : null; })}</svg>{positions.map(({ node, x, y }) => <div className={`node ${pretty(node.kind)}`} style={{ left: `${x}%`, top: `${y}%` }} key={pretty(node.id)}><b>{pretty(node.kind)}</b><span>{pretty(node.id)}</span></div>)}</div>
    {!nodes.length && <div className="graph-empty"><span>◎</span><b>Evidence graph ready</b><small>Run an investigation to populate connected packet, flow, alert, and claim evidence.</small></div>}
  </div>;
}

function Feed({ events, compact = false }: { events: EventMessage[]; compact?: boolean }) {
  if (!events.length) return <div className="empty-feed"><span>◌</span><b>Waiting for live activity</b><small>CLI and API investigations will appear here in real time.</small></div>;
  return <div className={`feed ${compact ? "compact" : ""}`}>{events.slice(-12).reverse().map((event, index) => <div className="feed-row" key={`${event.ts}-${index}`}><i className={event.event.includes("failed") ? "danger" : event.event.includes("complete") ? "success" : ""}/><div><div className="feed-heading"><b>{eventLabel(event.event)}</b><time>{new Date(event.ts * 1000).toLocaleTimeString()}</time></div><small>{JSON.stringify(event.payload)}</small></div></div>)}</div>;
}

function PacketTable({ packets, onSelect }: { packets: Packet[]; onSelect: (packet: Packet) => void }) {
  if (!packets.length) return <div className="empty-state"><span>⌁</span><b>No packet data loaded</b><small>Select a session with a readable PCAP to inspect packet evidence.</small></div>;
  return <div className="table-wrap"><table><thead><tr><th>#</th><th>TIME</th><th>PROTOCOL</th><th>SOURCE</th><th>DESTINATION</th><th>BYTES</th></tr></thead><tbody>{packets.map(packet => <tr onClick={() => onSelect(packet)} key={packet.index}><td>#{packet.index}</td><td>{new Date((packet.timestamp || 0) * 1000).toLocaleTimeString()}</td><td><span className="protocol">{pretty(packet.protocol)}</span></td><td>{pretty(packet.src_ip)}{packet.src_port ? `:${packet.src_port}` : ""}</td><td>{pretty(packet.dst_ip)}{packet.dst_port ? `:${packet.dst_port}` : ""}</td><td>{pretty(packet.length)}</td></tr>)}</tbody></table></div>;
}

function AlertTable({ alerts, onAcknowledge }: { alerts: Alert[]; onAcknowledge: (alert: Alert, index: number) => void }) {
  if (!alerts.length) return <div className="empty-state"><span>✓</span><b>No active alerts</b><small>New detector and investigation alerts will appear here.</small></div>;
  return <div className="table-wrap"><table><thead><tr><th>STATUS</th><th>EVENT</th><th>SESSION</th><th>DETAIL</th><th/></tr></thead><tbody>{alerts.map((alert, index) => <tr key={`${alert.session}-${index}`}><td><span className="severity high">{alert.event?.includes("failed") ? "HIGH" : "NOTICE"}</span></td><td>{eventLabel(alert.event ?? "alert")}</td><td>{pretty(alert.session)}</td><td className="truncate">{JSON.stringify(alert.payload ?? {})}</td><td><button className="ack" onClick={() => onAcknowledge(alert, index)}>Acknowledge</button></td></tr>)}</tbody></table></div>;
}

function App() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [events, setEvents] = useState<EventMessage[]>([]);
  const [selected, setSelected] = useState<Session | null>(null);
  const [graph, setGraph] = useState<Graph>({});
  const [question, setQuestion] = useState("Analyze the suspicious activity in this capture.");
  const [theme, setTheme] = useState(false);
  const [roi, setRoi] = useState<Record<string, unknown>>({});
  const [zoom, setZoom] = useState(1);
  const [query, setQuery] = useState("");
  const [activeView, setActiveView] = useState("overview");
  const [running, setRunning] = useState(false);
  const [packets, setPackets] = useState<Packet[]>([]);
  const [packetQuery, setPacketQuery] = useState("");
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
  const [apiAlerts, setApiAlerts] = useState<Alert[]>([]);
  const [error, setError] = useState("");
  const [reports, setReports] = useState<Report[]>([]);

  useEffect(() => {
    fetch("/api/v1/sessions").then(response => response.json()).then(data => { const list = data.sessions ?? []; setSessions(list); if (list[0]) setSelected(list[0]); }).catch(() => undefined);
    fetch("/api/v1/analytics/roi").then(response => response.json()).then(setRoi).catch(() => undefined);
    fetch("/api/v1/alerts").then(response => response.json()).then(data => setApiAlerts(data.alerts ?? [])).catch(() => undefined);
    const socket = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws/live`);
    socket.onmessage = message => { const next = JSON.parse(message.data) as EventMessage & { event: string; payload: { events?: EventMessage[] } }; if (next.event === "snapshot") setEvents(next.payload.events ?? []); else setEvents(old => [...old.slice(-99), next]); };
    return () => socket.close();
  }, []);
  useEffect(() => { if (!selected) return; fetch(`/api/v1/session/${selected.key}/graph`).then(response => response.json()).then(data => setGraph(data.graph ?? {})).catch(() => setGraph({})); }, [selected]);
  useEffect(() => { if (!selected) return; fetch(`/api/v1/session/${selected.key}`).then(response => response.json()).then(data => setReports(data.reports ?? [])).catch(() => setReports([])); }, [selected]);
  useEffect(() => { if (!selected) return; fetch(`/api/v1/session/${selected.key}/packets?limit=250&query=${encodeURIComponent(packetQuery)}`).then(response => response.json()).then(data => setPackets(data.packets ?? [])).catch(() => setPackets([])); }, [selected, packetQuery]);

  const visibleSessions = sessions.filter(session => `${session.key} ${session.pcap_path}`.toLowerCase().includes(query.toLowerCase()));
  const investigationEvents = useMemo(() => events.filter(event => event.event.includes("investigation") || event.event.includes("hypothesis")), [events]);
  const alerts = [...apiAlerts, ...events.filter(event => event.event.includes("alert") || event.event.includes("failed")).map(event => ({ event: event.event, payload: event.payload, session: pretty(event.payload.session) }))];
  const investigate = () => { if (!selected) return; setRunning(true); setError(""); fetch("/api/v1/investigate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ session: selected.key, question }) }).then(response => { if (!response.ok) throw new Error("Investigation could not be queued"); setActiveView("investigations"); }).catch(exception => setError(String(exception))).finally(() => setRunning(false)); };
  const acknowledge = (alert: Alert, index: number) => { if (!alert.session) return; fetch(`/api/v1/session/${alert.session}/alerts/${index}/ack`, { method: "POST" }).then(() => setApiAlerts(old => old.filter((_, item) => item !== index))).catch(exception => setError(String(exception))); };

  return <main className={theme ? "light" : ""}><div className="app-shell">
    <aside className="sidebar"><div className="brand"><div className="brand-mark">E</div><div><b>Easy<span>Shark</span></b><small>ANALYST WORKSPACE</small></div></div><div className="side-label">WORKSPACE</div><nav>{[["overview", "▦", "Overview"], ["investigations", "⌁", "Investigations"], ["evidence", "◇", "Evidence graph"], ["alerts", "!", "Alerts"]].map(([id, icon, label]) => <button className={activeView === id ? "active" : ""} onClick={() => setActiveView(id)} key={id}><Icon>{icon}</Icon>{label}{id === "alerts" && alerts.length > 0 && <em>{alerts.length}</em>}</button>)}</nav><div className="side-label">SYSTEM</div><nav><button onClick={() => setTheme(!theme)}><Icon>{theme ? "☾" : "☼"}</Icon>{theme ? "Dark theme" : "Light theme"}</button><button><Icon>⚙</Icon>Settings</button></nav><div className="sidebar-footer"><span className="online-dot"/> Engine online<small>API v1 · live bus connected</small></div></aside>
    <section className="workspace"><header className="topbar"><div className="crumb"><span>Workspace</span><b>/</b><strong>{activeView === "overview" ? "Overview" : eventLabel(activeView)}</strong></div><div className="top-actions"><div className="live-pill"><i/> LIVE <span>BUS</span></div><button className="avatar">SA</button></div></header>
      <div className="content"><div className="page-heading"><div><span className="eyebrow">SECURITY OPERATIONS CENTER</span><h1>Investigation overview</h1><p>Monitor captures, follow evidence, and coordinate live AI investigations.</p></div><button className="outline" onClick={() => window.location.reload()}>↻ Refresh data</button></div>
        {error && <div className="error-banner">⚠ {error}</div>}
        <div className={activeView === "overview" ? "" : "hidden"}><section className="metrics"><article><div className="metric-icon blue">◈</div><div><small>CAPTURE SESSIONS</small><strong>{sessions.length}</strong><span className="trend">↗ active workspace</span></div></article><article><div className="metric-icon orange">!</div><div><small>LIVE ALERTS</small><strong>{alerts.length}</strong><span className={alerts.length ? "trend warn" : "trend"}>{alerts.length ? "needs attention" : "no open alerts"}</span></div></article><article><div className="metric-icon purple">⌁</div><div><small>BUS EVENTS</small><strong>{events.length}</strong><span className="trend">real-time stream</span></div></article><article><div className="metric-icon green">◷</div><div><small>REVIEW MINUTES SAVED</small><strong>{pretty(roi.estimated_review_minutes_saved ?? 0)}</strong><span className="trend">automated analysis</span></div></article></section>
        <div className="dashboard-grid"><section className="panel session-panel"><div className="panel-title"><div><h2>Capture sessions</h2><span>Historical and active investigations</span></div><b className="count">{sessions.length}</b></div><div className="search"><span>⌕</span><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search sessions or PCAP paths..."/></div>{visibleSessions.length ? <div className="session-list">{visibleSessions.map(session => <button className={`session-card ${selected?.key === session.key ? "selected" : ""}`} onClick={() => setSelected(session)} key={session.key}><span className="session-status"/><div><b>{session.key}</b><small title={session.pcap_path}>{session.pcap_path}</small><time>{session.last_active}</time></div><span className="chevron">›</span></button>)}</div> : <div className="empty-state"><span>⌁</span><b>No sessions found</b><small>Start EasyShark with a PCAP or adjust your search.</small></div>}</section>
          <section className="panel graph-panel"><div className="panel-title"><div><h2>Evidence graph</h2><span>{graph.nodes?.length ?? 0} connected evidence nodes</span></div><button className="outline small-button" disabled={!selected}>Open explorer ↗</button></div><GraphView graph={graph} zoom={zoom} setZoom={setZoom}/></section></div>
        <div className="bottom-grid"><section className="panel console-panel"><div className="panel-title"><div><h2>AI investigation console</h2><span>{selected ? `Targeting ${selected.key}` : "Select a capture session to begin"}</span></div><span className="secure-badge">● DETERMINISTIC BUS</span></div><div className="console-intro"><span className="console-mark">✦</span><div><b>Ask EasyShark to investigate</b><small>Questions are executed against the selected capture and streamed to the war-room.</small></div></div><textarea aria-label="Investigation question" value={question} onChange={event => setQuestion(event.target.value)} placeholder="What should we investigate?"/><div className="console-footer"><span>Enter a focused question for better evidence</span><button className="primary" disabled={!selected || running} onClick={investigate}>{running ? "Starting…" : "Run investigation  ↗"}</button></div><div className="section-label">INVESTIGATION TRACE</div><Feed events={investigationEvents} compact/></section>
          <section className="panel feed-panel"><div className="panel-title"><div><h2>War-room activity</h2><span>All connected analysts and agents</span></div><span className="live-label"><i/> streaming</span></div><Feed events={events}/></section></div></div>
        {activeView === "investigations" && <section className="panel full-view"><div className="panel-title"><div><h2>Investigation console</h2><span>Submit and follow long-running analysis jobs</span></div></div><div className="wide-console"><textarea value={question} onChange={event => setQuestion(event.target.value)} /><button className="primary" disabled={!selected || running} onClick={investigate}>{running ? "Starting…" : "Run investigation ↗"}</button></div><div className="section-label">LIVE TRACE</div><Feed events={investigationEvents}/><div className="section-label">REPORTS</div><div className="report-list">{reports.length ? reports.map(report => <div className="report-row" key={report.file}><b>{report.file}</b><span>{pretty(report.timestamp)}</span><div>{["json", "markdown", "sigma", "spl"].map(format => <a href={`/api/v1/session/${selected?.key}/report/${encodeURIComponent(report.file)}?format=${format}`} key={format}>{format.toUpperCase()}</a>)}</div></div>) : <span className="muted">Reports will appear after an investigation completes.</span>}</div></section>}
        {activeView === "evidence" && <section className="panel full-view"><div className="panel-title"><div><h2>Packet evidence</h2><span>{selected ? selected.pcap_path : "Select a session"}</span></div><input className="table-search" value={packetQuery} onChange={event => setPacketQuery(event.target.value)} placeholder="Filter protocol, IP, port..."/></div><PacketTable packets={packets} onSelect={setSelectedPacket}/>{selectedPacket && <div className="packet-detail"><b>Packet #{selectedPacket.index}</b><span>{pretty(selectedPacket.protocol)} · {pretty(selectedPacket.length)} bytes</span><code>{selectedPacket.payload_hex || "No payload"}</code></div>}</section>}
        {activeView === "alerts" && <section className="panel full-view"><div className="panel-title"><div><h2>Alert center</h2><span>Review, acknowledge, and triage active signals</span></div><b className="count">{alerts.length}</b></div><AlertTable alerts={alerts} onAcknowledge={acknowledge}/></section>}
      </div></section>
  </div></main>;
}

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
