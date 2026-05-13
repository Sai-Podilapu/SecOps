import { useState, useMemo } from "react";
import './index.css';

// ─── Shared UI ────────────────────────────────────────────────────────────────
function Badge({ type = "neutral", children, small }) {
  const m = {
    red:     { bg:"var(--red-dim)",    color:"var(--red)",    border:"var(--red-b)" },
    orange:  { bg:"var(--orange-dim)", color:"var(--orange)", border:"var(--orange-b)" },
    yellow:  { bg:"var(--yellow-dim)", color:"var(--yellow)", border:"var(--yellow-b)" },
    green:   { bg:"var(--green-dim)",  color:"var(--green)",  border:"var(--green-b)" },
    purple:  { bg:"var(--purple-dim)", color:"var(--purple)", border:"var(--purple-b)" },
    cyan:    { bg:"var(--cyan-dim)",   color:"var(--cyan)",   border:"var(--cyan-b)" },
    accent:  { bg:"var(--accent-dim)", color:"var(--accent)", border:"#1e3a5f" },
    neutral: { bg:"var(--surface-3)",  color:"var(--text-2)", border:"var(--border)" },
  };
  const s = m[type] || m.neutral;
  return (
    <span style={{ display:"inline-block", padding:small?"1px 6px":"2px 8px", borderRadius:10,
      fontSize:small?10:11, fontWeight:500, background:s.bg, color:s.color,
      border:`1px solid ${s.border}`, whiteSpace:"nowrap" }}>
      {children}
    </span>
  );
}

const severityBadge = sev => {
  const m={CRITICAL:"red",HIGH:"orange",MEDIUM:"yellow",LOW:"neutral",INFORMATIONAL:"neutral",INFO:"neutral"};
  return <Badge type={m[sev]||"neutral"}>{sev}</Badge>;
};
const statusBadge = s => {
  const u=(s||"").toUpperCase();
  if(u==="PASS"||u==="COMPLIANT")      return <Badge type="green">{s}</Badge>;
  if(u==="FAIL"||u==="NON_COMPLIANT")  return <Badge type="red">{s}</Badge>;
  if(u==="NOT_APPLICABLE")             return <Badge type="neutral">{s}</Badge>;
  return <Badge type="yellow">{s}</Badge>;
};
const sourceBadge = src => {
  const m={"Inspector":"purple","Macie":"cyan","Security Hub":"accent","GuardDuty":"orange"};
  return <Badge type={m[src]||"neutral"}>{src}</Badge>;
};

const Mono = ({ children, size=11 }) =>
  <span style={{ fontFamily:"var(--font-mono)", fontSize:size }}>{children}</span>;

const Empty = ({ message="No data." }) => (
  <div style={{ padding:"32px 24px", textAlign:"center", color:"var(--text-3)", fontSize:13,
    border:"1px solid var(--border)", borderRadius:"var(--radius)", background:"var(--surface)" }}>
    {message}
  </div>
);

const Card = ({ children, style }) =>
  <div style={{ background:"var(--surface)", border:"1px solid var(--border)",
    borderRadius:"var(--radius)", ...style }}>{children}</div>;

const SectionTitle = ({ children }) =>
  <div style={{ fontSize:10, fontWeight:600, textTransform:"uppercase", letterSpacing:"0.08em",
    color:"var(--text-3)", marginBottom:10 }}>{children}</div>;

function StatGrid({ stats }) {
  return (
    <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill,minmax(130px,1fr))", gap:1,
      background:"var(--border)", border:"1px solid var(--border)", borderRadius:"var(--radius)", overflow:"hidden" }}>
      {stats.map(({ label, value, color, accent }) => (
        <div key={label} style={{ background:"var(--surface)", padding:"14px 16px" }}>
          <div style={{ fontSize:20, fontWeight:700, fontFamily:"var(--font-mono)",
            letterSpacing:"-0.02em", color:color||(accent?"var(--accent)":"var(--text-1)") }}>{value}</div>
          <div style={{ fontSize:11, color:"var(--text-2)", marginTop:3 }}>{label}</div>
        </div>
      ))}
    </div>
  );
}

const tdS = { padding:"8px 14px", borderBottom:"1px solid var(--border)",
  overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap", maxWidth:200 };

function TableComp({ columns, rows, maxHeight }) {
  if (!rows?.length) return <Empty />;
  return (
    <div style={{ overflowX:"auto", overflowY:maxHeight?"auto":"visible", maxHeight,
      border:"1px solid var(--border)", borderRadius:"var(--radius)" }}>
      <table style={{ width:"100%", borderCollapse:"collapse", fontSize:12 }}>
        <thead style={{ position:maxHeight?"sticky":"static", top:0, zIndex:1 }}>
          <tr style={{ background:"var(--surface-2)" }}>
            {columns.map((c,i)=>(
              <th key={i} style={{ padding:"8px 14px", textAlign:"left", fontWeight:600,
                color:"var(--text-2)", borderBottom:"1px solid var(--border)", whiteSpace:"nowrap",
                fontSize:10, textTransform:"uppercase", letterSpacing:"0.06em" }}>{c}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row,ri)=>(
            <tr key={ri} style={{ background:ri%2===0?"var(--surface)":"var(--surface-2)" }}>
              {row.map((cell,ci)=>(
                <td key={ci} style={tdS}>{cell??'—'}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ScoreRing({ score, size=80, label }) {
  const r=(size/2)-8, circ=2*Math.PI*r, dash=(score/100)*circ;
  const color=score>=80?"var(--green)":score>=60?"var(--yellow)":"var(--red)";
  return (
    <div style={{ display:"flex", flexDirection:"column", alignItems:"center", gap:6 }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="var(--surface-3)" strokeWidth="6"/>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth="6"
          strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
          transform={`rotate(-90 ${size/2} ${size/2})`}
          style={{ transition:"stroke-dasharray 0.6s ease" }}/>
        <text x={size/2} y={size/2+1} textAnchor="middle" dominantBaseline="middle"
          fill={color} fontSize={size<70?12:15} fontWeight="700" fontFamily="IBM Plex Mono,monospace">
          {score}%
        </text>
      </svg>
      {label && <span style={{ fontSize:11, color:"var(--text-2)", textAlign:"center" }}>{label}</span>}
    </div>
  );
}

function RiskGauge({ score, level }) {
  const color=level==="CRITICAL"?"var(--red)":level==="HIGH"?"var(--orange)":level==="MEDIUM"?"var(--yellow)":"var(--green)";
  const r=46, circ=2*Math.PI*r, dash=(score/100)*circ;
  return (
    <div style={{ display:"flex", flexDirection:"column", alignItems:"center", gap:8 }}>
      <svg width="120" height="120" viewBox="0 0 120 120">
        <circle cx="60" cy="60" r={r} fill="none" stroke="var(--surface-3)" strokeWidth="8"/>
        <circle cx="60" cy="60" r={r} fill="none" stroke={color} strokeWidth="8"
          strokeDasharray={`${dash} ${circ}`} strokeLinecap="round" transform="rotate(-90 60 60)"
          style={{ transition:"stroke-dasharray 0.8s ease", filter:`drop-shadow(0 0 8px ${color})` }}/>
        <text x="60" y="54" textAnchor="middle" dominantBaseline="middle"
          fill={color} fontSize="18" fontWeight="700" fontFamily="IBM Plex Mono,monospace">{score}%</text>
        <text x="60" y="72" textAnchor="middle" dominantBaseline="middle"
          fill={color} fontSize="11" fontFamily="DM Sans,sans-serif">{level}</text>
      </svg>
      <span style={{ fontSize:11, color:"var(--text-2)" }}>Overall Risk Score</span>
    </div>
  );
}

function MiniBar({ value, max, color="var(--red)" }) {
  const pct = max>0 ? (value/max)*100 : 0;
  return (
    <div style={{ display:"flex", alignItems:"center", gap:8 }}>
      <div style={{ flex:1, height:4, background:"var(--surface-3)", borderRadius:2, overflow:"hidden" }}>
        <div style={{ width:`${pct}%`, height:"100%", background:color, borderRadius:2, transition:"width 0.5s ease" }}/>
      </div>
      <span style={{ fontFamily:"var(--font-mono)", fontSize:11, fontWeight:600, color, minWidth:24, textAlign:"right" }}>{value}</span>
    </div>
  );
}

function CheckList({ checks }) {
  if (!checks?.length) return <Empty message="No checks performed." />;
  return (
    <div style={{ border:"1px solid var(--border)", borderRadius:"var(--radius)", overflow:"hidden" }}>
      {checks.map((c,i)=>(
        <div key={i} style={{ display:"flex", alignItems:"flex-start", gap:12, padding:"10px 14px",
          background:i%2===0?"var(--surface)":"var(--surface-2)",
          borderBottom:i<checks.length-1?"1px solid var(--border)":"none" }}>
          <span style={{ fontSize:14, flexShrink:0, marginTop:1, color:c.status==="PASS"?"var(--green)":"var(--red)" }}>
            {c.status==="PASS"?"✓":"✗"}
          </span>
          <div style={{ flex:1 }}>
            <div style={{ fontSize:12, fontWeight:500, marginBottom:2 }}>{c.name}</div>
            <div style={{ fontSize:11, color:"var(--text-2)" }}>{c.detail}</div>
          </div>
          <div style={{ flexShrink:0 }}>{severityBadge(c.severity)}</div>
        </div>
      ))}
    </div>
  );
}

function TabBar({ tabs, active, setActive }) {
  return (
    <div style={{ display:"flex", gap:1, background:"var(--border)", borderRadius:"var(--radius-sm)",
      overflow:"hidden", width:"fit-content" }}>
      {tabs.map(t=>(
        <button key={t.id} onClick={()=>setActive(t.id)} style={{ padding:"5px 14px", fontSize:11,
          border:"none", cursor:"pointer", background:active===t.id?"var(--surface)":"transparent",
          color:active===t.id?"var(--text-1)":"var(--text-3)", fontFamily:"var(--font-sans)",
          fontWeight:active===t.id?500:400 }}>{t.label}</button>
      ))}
    </div>
  );
}

function PagBtn({ children, onClick, disabled, active }) {
  return (
    <button onClick={onClick} disabled={disabled} style={{ padding:"5px 10px", fontSize:12,
      borderRadius:"var(--radius-sm)", border:"1px solid var(--border)",
      background:active?"var(--accent)":"var(--surface)",
      color:active?"#fff":disabled?"var(--text-3)":"var(--text-2)",
      cursor:disabled?"not-allowed":"pointer", fontFamily:"var(--font-sans)" }}>{children}</button>
  );
}

const REGIONS=['ap-south-1','ap-southeast-1','ap-southeast-2','ap-northeast-1','ap-northeast-2','ap-northeast-3',
  'eu-west-1','eu-west-2','eu-west-3','eu-central-1','eu-north-1','us-east-1','us-east-2',
  'us-west-1','us-west-2','ca-central-1','sa-east-1','me-south-1','af-south-1'];

// ─── Credentials Form ─────────────────────────────────────────────────────────
function CredentialsForm({ onScan, error, savedCreds, activeModule }) {
  const [accessKey, setAccessKey] = useState(savedCreds?.accessKey||"");
  const [secretKey, setSecretKey] = useState(savedCreds?.secretKey||"");
  const [region, setRegion]       = useState(savedCreds?.region||"");
  const [showSecret, setShowSecret] = useState(false);
  const valid = accessKey.trim() && secretKey.trim();

  const info = {
    discovery:   { label:"Asset Discovery Scan",      desc:"Discovers 300+ resource types via AWS Config", color:"var(--accent)" },
    compliance:  { label:"Compliance Check",           desc:"Config Rules, Security Hub, IAM, CloudTrail, GuardDuty", color:"var(--red)" },
    risk:        { label:"Risk Analysis Scan",         desc:"Inspector, Macie, GuardDuty, Health, CloudWatch", color:"var(--orange)" },
    remediation: { label:"Scan for Remediable Issues", desc:"Phase 4 — Scans for security issues and provides one-click remediation with full audit logging. Requires write permissions.", color:"var(--green)" },
    auto:        { label:"Auto Remediation Scan",      desc:"Phase 5 — Uses policies to detect issues and run automated fixes.", color:"var(--purple)" },
  }[activeModule] || { label:"Credentials", desc:"Enter your AWS credentials to continue.", color:"var(--purple)" };

  const inp = { background:"none", border:"none", outline:"none",
    fontFamily:"var(--font-mono)", fontSize:12, color:"var(--text-1)", width:"100%" };

  return (
    <div style={{ width:"100%", maxWidth:460, animation:"fadeIn 0.4s ease" }}>
      <div style={{ marginBottom:28, textAlign:"center" }}>
        <div style={{ width:52, height:52, borderRadius:14, background:"var(--surface-2)",
          border:`1px solid ${info.color}30`, display:"flex", alignItems:"center", justifyContent:"center",
          margin:"0 auto 16px", boxShadow:`0 0 20px ${info.color}15` }}>
          {activeModule==="discovery" && <svg width="24" height="24" viewBox="0 0 24 24" fill="none"><path d="M3 16c4-2 14-2 18 0M8 12l4-7 4 7" stroke="var(--accent)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}
          {activeModule==="compliance" && <svg width="22" height="22" viewBox="0 0 22 22" fill="none"><path d="M11 2L4 6v4c0 4 3 7.5 7 8.8 4-1.3 7-4.8 7-8.8V6L11 2z" stroke="var(--red)" strokeWidth="1.7" strokeLinejoin="round"/><path d="M8 11l2 2 4-4" stroke="var(--red)" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"/></svg>}
          {activeModule==="risk" && <svg width="22" height="22" viewBox="0 0 22 22" fill="none"><path d="M11 3l2 6h6l-5 3.5 2 6L11 15l-5 3.5 2-6L3 9h6L11 3z" fill="var(--orange)" opacity=".9"/></svg>}
          {activeModule==="remediation" && <svg width="22" height="22" viewBox="0 0 22 22" fill="none"><path d="M5 11l4 4 8-8" stroke="var(--green)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/></svg>}
          {activeModule==="auto" && <svg width="22" height="22" viewBox="0 0 22 22" fill="none"><path d="M11 3l6 6h-4v6h-4v-6H5l6-6z" fill="var(--purple)" opacity=".9"/></svg>}
        </div>
        <h1 style={{ fontSize:20, fontWeight:700, letterSpacing:"-0.03em", marginBottom:6 }}>{info.label}</h1>
        <p style={{ color:"var(--text-2)", fontSize:13 }}>{info.desc}</p>
      </div>

      {error && (
        <div style={{ background:"var(--red-dim)", border:"1px solid var(--red-b)", borderRadius:"var(--radius)",
          padding:"10px 14px", marginBottom:16, fontSize:12, color:"var(--red)", display:"flex", gap:8 }}>
          <span>⚠</span><span>{error}</span>
        </div>
      )}

      <div style={{ background:"var(--surface)", border:"1px solid var(--border)", borderRadius:"var(--radius)", overflow:"hidden" }}>
        <div style={{ padding:"12px 16px" }}>
          <div style={{ fontSize:10, fontWeight:600, color:"var(--text-3)", marginBottom:6, textTransform:"uppercase", letterSpacing:"0.07em" }}>Access Key ID</div>
          <input autoFocus autoComplete="off" type="text" value={accessKey}
            onChange={e=>setAccessKey(e.target.value)} placeholder="AKIAIOSFODNN7EXAMPLE" style={inp}/>
        </div>
        <div style={{ height:1, background:"var(--border)" }}/>
        <div style={{ padding:"12px 16px" }}>
          <div style={{ fontSize:10, fontWeight:600, color:"var(--text-3)", marginBottom:6, textTransform:"uppercase", letterSpacing:"0.07em" }}>Secret Access Key</div>
          <div style={{ display:"flex", alignItems:"center", gap:8 }}>
            <input autoComplete="off" type={showSecret?"text":"password"} value={secretKey}
              onChange={e=>setSecretKey(e.target.value)} placeholder="wJalrXUtnFEMI/K7MDENG/…" style={{ ...inp, flex:1 }}/>
            <button onClick={()=>setShowSecret(s=>!s)} style={{ background:"none", border:"none", cursor:"pointer",
              color:"var(--text-3)", fontSize:11, fontFamily:"var(--font-sans)", flexShrink:0 }}>
              {showSecret?"hide":"show"}
            </button>
          </div>
        </div>
        <div style={{ height:1, background:"var(--border)" }}/>
        <div style={{ padding:"12px 16px" }}>
          <div style={{ fontSize:10, fontWeight:600, color:"var(--text-3)", marginBottom:6, textTransform:"uppercase", letterSpacing:"0.07em" }}>
            Region <span style={{ fontWeight:400, opacity:0.6 }}>(Optional)</span>
          </div>
          <select value={region} onChange={e=>setRegion(e.target.value)}
            style={{ ...inp, cursor:"pointer", color:region?"var(--text-1)":"var(--text-3)" }}>
            <option value="">All regions (recommended)</option>
            {REGIONS.map(r=><option key={r} value={r}>{r}</option>)}
          </select>
        </div>
      </div>

      <button disabled={!valid} onClick={()=>valid&&onScan({accessKey:accessKey.trim(),secretKey:secretKey.trim(),region})}
        style={{ width:"100%", marginTop:14, padding:"11px 0", background:valid?info.color:"var(--surface-2)",
          color:valid?"#fff":"var(--text-3)", border:"none", borderRadius:"var(--radius)",
          fontFamily:"var(--font-sans)", fontSize:13, fontWeight:600, cursor:valid?"pointer":"not-allowed",
          boxShadow:valid?`0 0 16px ${info.color}30`:"none", transition:"all 0.15s" }}>
        {info.label} →
      </button>

      <div style={{ display:"flex", gap:16, marginTop:14, justifyContent:"center" }}>
        {["Read-only access","Not stored","AWS SDK encrypted"].map(t=>(
          <span key={t} style={{ fontSize:11, color:"var(--text-3)", display:"flex", alignItems:"center", gap:4 }}>
            <span style={{ color:"var(--green)" }}>✓</span>{t}
          </span>
        ))}
      </div>
    </div>
  );
}

// ─── Scanning Screen ──────────────────────────────────────────────────────────
function Scanning({ activeModule }) {
  const info = {
    discovery:   { title:"Discovering AWS Resources",       color:"var(--accent)", step:"Querying AWS Config across all regions…" },
    compliance:  { title:"Running Compliance Checks",        color:"var(--red)",   step:"Checking Config Rules, Security Hub, IAM…" },
    risk:        { title:"Scanning for Risks",               color:"var(--orange)",step:"Inspector CVEs, Macie, GuardDuty, Health…" },
    remediation: { title:"Scanning for Remediable Issues",   color:"var(--green)", step:"Checking S3 buckets, security groups, IAM, GuardDuty…" },
  }[activeModule];
  return (
    <div style={{ display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", minHeight:"60vh", gap:24 }}>
      <div style={{ width:44, height:44, border:`2px solid var(--border)`, borderTop:`2px solid ${info.color}`,
        borderRadius:"50%", animation:"spin 0.8s linear infinite", boxShadow:`0 0 16px ${info.color}40` }}/>
      <div style={{ textAlign:"center" }}>
        <p style={{ fontWeight:600, fontSize:16, marginBottom:8 }}>{info.title}</p>
        <p style={{ color:info.color, fontSize:12, fontFamily:"var(--font-mono)", animation:"pulse 1.5s ease infinite" }}>{info.step}</p>
        <p style={{ color:"var(--text-3)", fontSize:12, marginTop:8 }}>This may take 1–3 minutes</p>
      </div>
    </div>
  );
}

// ─── Sidebar wrapper ──────────────────────────────────────────────────────────
function SidebarLayout({ nav, activeNav, setActiveNav, children, accentColor, meta, topInfo }) {
  return (
    <div style={{ display:"flex", minHeight:"calc(100vh - 108px)" }}>
      <aside style={{ width:210, borderRight:"1px solid var(--border)", background:"var(--surface)",
        padding:"16px 0", position:"sticky", top:108, height:"calc(100vh - 108px)", overflowY:"auto", flexShrink:0 }}>
        {topInfo && (
          <div style={{ padding:"0 16px 14px", borderBottom:"1px solid var(--border)", marginBottom:8 }}>
            {topInfo.map(([label,val])=>(
              <div key={label} style={{ marginBottom:5 }}>
                <div style={{ fontSize:10, color:"var(--text-3)" }}>{label}</div>
                <div style={{ fontFamily:"var(--font-mono)", fontSize:11, fontWeight:500, marginTop:1,
                  overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{val||"—"}</div>
              </div>
            ))}
            {meta && <div style={{ fontSize:10, color:"var(--text-3)", marginTop:4 }}>Scanned in {meta.duration}s</div>}
          </div>
        )}
        {nav.map(item => {
          const isA = activeNav===item.id;
          return (
            <button key={item.id} onClick={()=>setActiveNav(item.id)}
              style={{ display:"flex", alignItems:"center", justifyContent:"space-between", width:"100%",
                padding:"7px 16px", border:"none", cursor:"pointer", fontFamily:"var(--font-sans)", fontSize:13,
                borderLeft:isA?`2px solid ${accentColor}`:"2px solid transparent",
                background:isA?accentColor+"18":"none",
                color:isA?accentColor:"var(--text-2)", fontWeight:isA?500:400 }}>
              <span style={{ display:"flex", alignItems:"center", gap:8 }}>
                <span style={{ fontSize:12, opacity:0.7 }}>{item.icon}</span>{item.label}
              </span>
              {item.badge!=null && (
                <span style={{ fontFamily:"var(--font-mono)", fontSize:11, fontWeight:600,
                  color:item.badgeColor||accentColor }}>{item.badge}</span>
              )}
            </button>
          );
        })}
      </aside>
      <main style={{ flex:1, minWidth:0, padding:"24px 28px", animation:"fadeIn 0.3s ease", overflowX:"hidden" }}>
        {children}
      </main>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE 1 — ASSET DISCOVERY
// ═══════════════════════════════════════════════════════════════════════════════
function DiscoveryDashboard({ data, meta }) {
  const [active, setActive] = useState("overview");
  const total = Object.values(data.summary||{}).reduce((a,b)=>a+b,0);
  const recording = Object.values(data.config_status||{}).filter(s=>s.recording).length;

  const nav = [
    { id:"overview", label:"Overview",         icon:"◈" },
    { id:"explorer", label:"Resource Explorer", icon:"⊞" },
    { id:"regions",  label:"By Region",         icon:"◎" },
    { id:"costs",    label:"Cost & Usage",      icon:"◇" },
    { id:"config",   label:"Config Status",     icon:"◉" },
  ];

  return (
    <SidebarLayout nav={nav} activeNav={active} setActiveNav={setActive}
      accentColor="var(--accent)" meta={meta}
      topInfo={[["Account",data.identity?.account_id],["Regions",`${data.regions?.length} (${recording} recording)`],["Total Resources",total.toLocaleString()]]}>
      <div key={active}>
        {active==="overview" && <DiscoveryOverview data={data} meta={meta}/>}
        {active==="explorer" && <ResourceExplorer data={data}/>}
        {active==="regions"  && <RegionView data={data}/>}
        {active==="costs"    && <CostsSection costs={data.costs}/>}
        {active==="config"   && <ConfigStatus data={data}/>}
      </div>
    </SidebarLayout>
  );
}

function DiscoveryOverview({ data, meta }) {
  const summary=data.summary||{}, total=Object.values(summary).reduce((a,b)=>a+b,0);
  const recording=Object.values(data.config_status||{}).filter(s=>s.recording).length;
  const iamSum=data.iam_summary||{};
  const topTypes=Object.entries(summary).slice(0,12);
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:24 }}>
      <div>
        <h2 style={{ fontSize:16, fontWeight:700, letterSpacing:"-0.02em", marginBottom:4 }}>Resource Overview</h2>
        <p style={{ fontSize:12, color:"var(--text-2)" }}>{meta?.timestamp} · {data.scan_time}</p>
      </div>
      <StatGrid stats={[
        {label:"Total Resources",value:total.toLocaleString(),accent:true},
        {label:"Resource Types",value:Object.keys(summary).length},
        {label:"Regions Scanned",value:data.regions?.length||0},
        {label:"Regions Recording",value:recording},
        {label:"IAM Users",value:iamSum.users??'—'},
        {label:"IAM Roles",value:iamSum.roles??'—'},
        {label:"IAM Groups",value:iamSum.groups??'—'},
        {label:"Access Keys",value:iamSum.access_keys??'—'},
      ]}/>
      <Card style={{ padding:"14px 18px", display:"grid", gridTemplateColumns:"repeat(auto-fill,minmax(200px,1fr))", gap:14 }}>
        {[["Account ID",data.identity?.account_id],["ARN",data.identity?.arn],["Scan Time",data.scan_time]].map(([l,v])=>(
          <div key={l}><div style={{ fontSize:10, color:"var(--text-3)", marginBottom:3 }}>{l}</div>
          <div style={{ fontFamily:"var(--font-mono)", fontSize:11, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{v}</div></div>
        ))}
      </Card>
      {topTypes.length>0 && (
        <div>
          <SectionTitle>Top Resource Types</SectionTitle>
          <Card>{topTypes.map(([type,count],i)=>{
            const pct=(count/topTypes[0][1])*100;
            return (
              <div key={type} style={{ display:"flex", alignItems:"center", gap:12, padding:"9px 16px",
                borderBottom:i<topTypes.length-1?"1px solid var(--border)":"none" }}>
                <div style={{ width:24, textAlign:"right", fontFamily:"var(--font-mono)", fontSize:11,
                  color:"var(--text-3)", flexShrink:0 }}>{i+1}</div>
                <div style={{ flex:1, minWidth:0 }}>
                  <div style={{ fontSize:12, marginBottom:4, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{type}</div>
                  <div style={{ height:3, background:"var(--surface-3)", borderRadius:2, overflow:"hidden" }}>
                    <div style={{ width:`${pct}%`, height:"100%", background:"var(--accent)", transition:"width 0.5s" }}/>
                  </div>
                </div>
                <div style={{ fontFamily:"var(--font-mono)", fontSize:12, fontWeight:500, flexShrink:0 }}>{count}</div>
              </div>
            );
          })}</Card>
        </div>
      )}
    </div>
  );
}

function ResourceExplorer({ data }) {
  const [search,setSearch]=useState(""), [selType,setSelType]=useState(""), [selRegion,setSelRegion]=useState(""), [page,setPage]=useState(1);
  const PAGE=50;
  const allResources=useMemo(()=>{
    const flat=[];
    for(const [region,typeMap] of Object.entries(data.resources||{}))
      for(const [rtype,items] of Object.entries(typeMap))
        for(const item of items) flat.push({...item,resourceType:rtype,region:item.region||region});
    return flat;
  },[data.resources]);
  const allTypes=useMemo(()=>[...new Set(allResources.map(r=>r.resourceType))].sort(),[allResources]);
  const allRegions=useMemo(()=>[...new Set(allResources.map(r=>r.region))].sort(),[allResources]);
  const filtered=useMemo(()=>allResources.filter(r=>{
    const q=search.toLowerCase();
    return (!q||[r.resourceId,r.resourceName,r.resourceType,r.region].some(v=>v?.toLowerCase().includes(q)))
      && (!selType||r.resourceType===selType) && (!selRegion||r.region===selRegion);
  }),[allResources,search,selType,selRegion]);
  const totalPages=Math.ceil(filtered.length/PAGE), paged=filtered.slice((page-1)*PAGE,page*PAGE);
  const SS={ background:"var(--surface)", border:"1px solid var(--border)", borderRadius:"var(--radius-sm)",
    padding:"7px 10px", fontSize:12, color:"var(--text-1)", fontFamily:"var(--font-sans)", outline:"none", cursor:"pointer" };
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
      <div>
        <h2 style={{ fontSize:16, fontWeight:700, marginBottom:4 }}>Resource Explorer</h2>
        <p style={{ fontSize:12, color:"var(--text-2)" }}>{allResources.length.toLocaleString()} total · {filtered.length.toLocaleString()} shown</p>
      </div>
      <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
        <input value={search} onChange={e=>{setSearch(e.target.value);setPage(1);}} placeholder="Search ID, name, type, region…"
          style={{ flex:1, minWidth:200, ...SS, padding:"7px 12px" }}/>
        <select value={selType} onChange={e=>{setSelType(e.target.value);setPage(1);}} style={SS}>
          <option value="">All types ({allTypes.length})</option>
          {allTypes.map(t=><option key={t} value={t}>{t}</option>)}
        </select>
        <select value={selRegion} onChange={e=>{setSelRegion(e.target.value);setPage(1);}} style={SS}>
          <option value="">All regions</option>
          {allRegions.map(r=><option key={r} value={r}>{r}</option>)}
        </select>
        {(search||selType||selRegion) && (
          <button onClick={()=>{setSearch("");setSelType("");setSelRegion("");setPage(1);}} style={{ ...SS, color:"var(--text-2)" }}>Clear</button>
        )}
      </div>
      {paged.length===0 ? <Empty message="No resources match your filters."/> : (
        <div style={{ border:"1px solid var(--border)", borderRadius:"var(--radius)", overflow:"hidden" }}>
          <div style={{ overflowX:"auto", maxHeight:"calc(100vh - 340px)", overflowY:"auto" }}>
            <table style={{ width:"100%", borderCollapse:"collapse", fontSize:12 }}>
              <thead style={{ position:"sticky", top:0, zIndex:1 }}>
                <tr style={{ background:"var(--surface-2)" }}>
                  {["Resource ID","Name","Type","Region","AZ","Created"].map((c,i)=>(
                    <th key={i} style={{ padding:"8px 14px", textAlign:"left", fontWeight:600, color:"var(--text-2)",
                      borderBottom:"1px solid var(--border)", whiteSpace:"nowrap", fontSize:10, textTransform:"uppercase", letterSpacing:"0.06em" }}>{c}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {paged.map((r,ri)=>(
                  <tr key={ri} style={{ background:ri%2===0?"var(--surface)":"var(--surface-2)" }}>
                    <td style={tdS}><Mono>{r.resourceId}</Mono></td>
                    <td style={tdS}>{r.resourceName!=="—"?r.resourceName:<span style={{ color:"var(--text-3)" }}>—</span>}</td>
                    <td style={{ ...tdS, maxWidth:220 }}><span style={{ fontSize:11, color:"var(--text-2)", fontFamily:"var(--font-mono)" }}>{r.resourceType}</span></td>
                    <td style={tdS}><Mono>{r.region}</Mono></td>
                    <td style={tdS}><span style={{ fontSize:11, color:"var(--text-3)" }}>{r.az||"—"}</span></td>
                    <td style={tdS}><span style={{ fontSize:11, color:"var(--text-3)" }}>{r.createdAt?.slice(0,10)||"—"}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      {totalPages>1 && (
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
          <span style={{ fontSize:12, color:"var(--text-2)" }}>Page {page} of {totalPages}</span>
          <div style={{ display:"flex", gap:6 }}>
            <PagBtn disabled={page<=1} onClick={()=>setPage(p=>p-1)}>← Prev</PagBtn>
            {Array.from({length:Math.min(5,totalPages)},(_,i)=>{
              const pg=Math.max(1,Math.min(page-2,totalPages-4))+i;
              return pg<=totalPages?<PagBtn key={pg} active={pg===page} onClick={()=>setPage(pg)}>{pg}</PagBtn>:null;
            })}
            <PagBtn disabled={page>=totalPages} onClick={()=>setPage(p=>p+1)}>Next →</PagBtn>
          </div>
        </div>
      )}
    </div>
  );
}

function RegionView({ data }) {
  const regions=data.regions||[];
  const [activeRegion,setActiveRegion]=useState(regions[0]||"");
  const [activeType,setActiveType]=useState("");
  const regionData=data.resources?.[activeRegion]||{};
  const regionCounts=data.resource_counts?.[activeRegion]||{};
  const configStatus=data.config_status?.[activeRegion]||{};
  const totalInRegion=Object.values(regionCounts).reduce((a,b)=>a+b,0);
  const types=Object.keys(regionData).sort();
  const currentType=activeType&&regionData[activeType]?activeType:types[0]||"";
  const items=regionData[currentType]||[];
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
      <h2 style={{ fontSize:16, fontWeight:700 }}>By Region</h2>
      <div style={{ display:"flex", gap:14 }}>
        <div style={{ width:150, flexShrink:0 }}>
          <SectionTitle>Regions ({regions.length})</SectionTitle>
          <div style={{ border:"1px solid var(--border)", borderRadius:"var(--radius)", overflow:"hidden" }}>
            {regions.map((r,i)=>{
              const count=Object.values(data.resource_counts?.[r]||{}).reduce((a,b)=>a+b,0), isA=r===activeRegion;
              return (
                <button key={r} onClick={()=>{setActiveRegion(r);setActiveType("");}}
                  style={{ display:"flex", justifyContent:"space-between", alignItems:"center", width:"100%",
                    padding:"7px 10px", fontSize:11, fontFamily:"var(--font-mono)", border:"none",
                    borderBottom:i<regions.length-1?"1px solid var(--border)":"none",
                    background:isA?"var(--accent-dim)":i%2===0?"var(--surface)":"var(--surface-2)",
                    color:isA?"var(--accent)":"var(--text-2)", cursor:"pointer",
                    borderLeft:isA?"2px solid var(--accent)":"2px solid transparent" }}>
                  <span>{r}</span>
                  {count>0&&<span style={{ fontSize:10 }}>{count}</span>}
                </button>
              );
            })}
          </div>
        </div>
        <div style={{ flex:1, minWidth:0 }}>
          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:12 }}>
            <div>
              <SectionTitle>{activeRegion}</SectionTitle>
              <span style={{ fontSize:12, color:"var(--text-2)" }}>{totalInRegion} resources · {types.length} types</span>
            </div>
            <Badge type={configStatus.recording?"green":configStatus.enabled?"yellow":"neutral"}>
              {configStatus.recording?"Recording":configStatus.enabled?"Paused":"Off"}
            </Badge>
          </div>
          {types.length===0 ? <Empty message="No resources in this region."/> : (
            <>
              <div style={{ display:"flex", flexWrap:"wrap", gap:5, marginBottom:14 }}>
                {types.map(t=>{const isA=t===currentType;return(
                  <button key={t} onClick={()=>setActiveType(t)}
                    style={{ padding:"4px 10px", fontSize:11, border:`1px solid ${isA?"var(--accent)":"var(--border)"}`,
                      borderRadius:"var(--radius-sm)", cursor:"pointer",
                      background:isA?"var(--accent-dim)":"var(--surface)",
                      color:isA?"var(--accent)":"var(--text-2)", fontFamily:"var(--font-sans)", fontWeight:isA?500:400 }}>
                    {t.replace("AWS::","").split("::").pop()} ({regionData[t]?.length||0})
                  </button>
                );})}
              </div>
              <div style={{ fontSize:13, fontWeight:500, marginBottom:10, color:"var(--text-2)" }}>
                {currentType} — <span style={{ fontFamily:"var(--font-mono)", fontSize:11 }}>{items.length} resources</span>
              </div>
              <TableComp maxHeight="calc(100vh - 440px)"
                columns={["Resource ID","Name","AZ","Created"]}
                rows={items.map(item=>[
                  <Mono>{item.resourceId}</Mono>,
                  item.resourceName!=="—"?item.resourceName:"—",
                  <span style={{ fontSize:11, color:"var(--text-3)" }}>{item.az||"—"}</span>,
                  <span style={{ fontSize:11, color:"var(--text-3)" }}>{item.createdAt?.slice(0,10)||"—"}</span>
                ])}/>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function CostsSection({ costs }) {
  const [view,setView]=useState("service");
  if(!costs) return <Empty message="No cost data available."/>;
  const byService=Object.entries(costs.by_service||{}).sort((a,b)=>b[1]-a[1]);
  const byRegion=Object.entries(costs.by_region||{}).sort((a,b)=>b[1]-a[1]);
  const entries=view==="service"?byService:byRegion;
  const maxVal=entries[0]?.[1]||1;
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
      <div>
        <h2 style={{ fontSize:16, fontWeight:700, marginBottom:4 }}>Cost & Usage</h2>
        <p style={{ fontSize:12, color:"var(--text-2)" }}>{costs.period}</p>
      </div>
      {costs.error && <div style={{ padding:"10px 14px", background:"var(--yellow-dim)", border:"1px solid var(--yellow-b)", borderRadius:"var(--radius-sm)", fontSize:12, color:"var(--yellow)" }}>⚠ {costs.error}</div>}
      <StatGrid stats={[
        {label:"Month-to-Date",value:`$${costs.total??'—'}`,accent:true},
        {label:"Forecast (EOM)",value:costs.forecast!=null?`$${costs.forecast}`:"—"},
        {label:"Services Billed",value:byService.length},
        {label:"Regions Billed",value:byRegion.length},
      ]}/>
      {entries.length>0 && (
        <div>
          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:12 }}>
            <SectionTitle>Breakdown</SectionTitle>
            <div style={{ display:"flex", gap:1, background:"var(--border)", borderRadius:"var(--radius-sm)", overflow:"hidden" }}>
              {["service","region"].map(v=>(
                <button key={v} onClick={()=>setView(v)} style={{ padding:"4px 12px", fontSize:11, border:"none", cursor:"pointer",
                  background:view===v?"var(--surface-2)":"transparent",
                  color:view===v?"var(--text-1)":"var(--text-3)", fontFamily:"var(--font-sans)", textTransform:"capitalize" }}>By {v}</button>
              ))}
            </div>
          </div>
          <Card>{entries.map(([name,cost],i)=>(
            <div key={name} style={{ display:"flex", alignItems:"center", gap:12, padding:"9px 16px",
              borderBottom:i<entries.length-1?"1px solid var(--border)":"none" }}>
              <div style={{ flex:1, minWidth:0 }}>
                <div style={{ fontSize:12, marginBottom:4, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{name}</div>
                <div style={{ height:3, background:"var(--surface-3)", borderRadius:2, overflow:"hidden" }}>
                  <div style={{ width:`${(cost/maxVal)*100}%`, height:"100%", background:"var(--accent)", transition:"width 0.5s" }}/>
                </div>
              </div>
              <div style={{ fontFamily:"var(--font-mono)", fontSize:12, fontWeight:500, flexShrink:0 }}>${cost.toFixed(4)}</div>
            </div>
          ))}</Card>
        </div>
      )}
    </div>
  );
}

function ConfigStatus({ data }) {
  const statuses=data.config_status||{}, regions=data.regions||[];
  const recording=regions.filter(r=>statuses[r]?.recording).length;
  const off=regions.filter(r=>!statuses[r]?.enabled).length;
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
      <div>
        <h2 style={{ fontSize:16, fontWeight:700, marginBottom:4 }}>AWS Config Status</h2>
        <p style={{ fontSize:12, color:"var(--text-2)" }}>Recorder status across {regions.length} regions</p>
      </div>
      <StatGrid stats={[
        {label:"Recording",value:recording,accent:true},
        {label:"Enabled/Paused",value:regions.filter(r=>statuses[r]?.enabled&&!statuses[r]?.recording).length},
        {label:"Not Configured",value:off,color:off>0?"var(--yellow)":undefined},
        {label:"Total Regions",value:regions.length},
      ]}/>
      {off>0 && <div style={{ padding:"12px 16px", background:"var(--yellow-dim)", border:"1px solid var(--yellow-b)", borderRadius:"var(--radius)", fontSize:12, color:"var(--yellow)" }}>
        <strong>{off} region{off>1?"s":""} not configured.</strong> Enable AWS Config to discover resources there.
      </div>}
      <div>
        <SectionTitle>Per-Region Status</SectionTitle>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill,minmax(280px,1fr))", gap:1,
          background:"var(--border)", border:"1px solid var(--border)", borderRadius:"var(--radius)", overflow:"hidden" }}>
          {regions.map(region=>{
            const s=statuses[region]||{};
            const count=Object.values(data.resource_counts?.[region]||{}).reduce((a,b)=>a+b,0);
            return (
              <div key={region} style={{ background:"var(--surface)", padding:"12px 16px",
                display:"flex", justifyContent:"space-between", alignItems:"flex-start" }}>
                <div>
                  <div style={{ fontFamily:"var(--font-mono)", fontSize:12, fontWeight:500, marginBottom:4 }}>{region}</div>
                  <div style={{ fontSize:11, color:"var(--text-3)" }}>{count>0?`${count} resources`:"No resources"}</div>
                </div>
                <Badge type={s.recording?"green":s.enabled?"yellow":"neutral"}>
                  {s.recording?"Recording":s.enabled?"Paused":"Off"}
                </Badge>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE 2 — COMPLIANCE
// ═══════════════════════════════════════════════════════════════════════════════
function ComplianceDashboard({ data, meta }) {
  const [active,setActive]=useState("overview");
  const summary=data.summary||{};
  const nav=[
    {id:"overview",  label:"Overview",         icon:"◈"},
    {id:"config",    label:"Config Rules",      icon:"◉", badge:data.config_rules?.score!=null?`${data.config_rules.score}%`:null, badgeColor:scoreColor(data.config_rules?.score)},
    {id:"hub",       label:"Security Hub",      icon:"⬡", badge:data.security_hub?.score!=null?`${data.security_hub.score}%`:null, badgeColor:scoreColor(data.security_hub?.score)},
    {id:"iam",       label:"IAM Compliance",    icon:"◎", badge:data.iam_compliance?.score!=null?`${data.iam_compliance.score}%`:null, badgeColor:scoreColor(data.iam_compliance?.score)},
    {id:"trail",     label:"CloudTrail",        icon:"◇", badge:data.cloudtrail?.score!=null?`${data.cloudtrail.score}%`:null, badgeColor:scoreColor(data.cloudtrail?.score)},
    {id:"guardduty", label:"GuardDuty",         icon:"◆", badge:data.guardduty?.score!=null?`${data.guardduty.score}%`:null, badgeColor:scoreColor(data.guardduty?.score)},
  ];
  return (
    <SidebarLayout nav={nav} activeNav={active} setActiveNav={setActive}
      accentColor="var(--red)" meta={meta}
      topInfo={[["Account",data.identity?.account_id],["Region",data.region],
        ["Critical",`${summary.critical_findings||0} findings`],["Overall",`${data.score?.overall||0}% (${data.score?.grade||"—"})`]]}>
      <div key={active}>
        {active==="overview"  && <ComplianceOverview data={data} meta={meta}/>}
        {active==="config"    && <ComplianceConfigRules data={data.config_rules}/>}
        {active==="hub"       && <ComplianceSecurityHub data={data.security_hub}/>}
        {active==="iam"       && <ComplianceIAM data={data.iam_compliance}/>}
        {active==="trail"     && <ComplianceCloudTrail data={data.cloudtrail}/>}
        {active==="guardduty" && <ComplianceGuardDuty data={data.guardduty}/>}
      </div>
    </SidebarLayout>
  );
}

const scoreColor = s => s==null?"var(--text-3)":s>=80?"var(--green)":s>=60?"var(--yellow)":"var(--red)";

function ComplianceOverview({ data, meta }) {
  const score=data.score||{}, summary=data.summary||{};
  const sections=[
    {label:"Config Rules",key:"config_rules"},{label:"Security Hub",key:"security_hub"},
    {label:"IAM",key:"iam_compliance"},{label:"CloudTrail",key:"cloudtrail"},{label:"GuardDuty",key:"guardduty"},
  ];
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:24 }}>
      <div>
        <h2 style={{ fontSize:16, fontWeight:700, marginBottom:4 }}>Compliance Overview</h2>
        <p style={{ fontSize:12, color:"var(--text-2)" }}>{meta?.timestamp} · {data.region} · {data.scan_time}</p>
      </div>
      <div style={{ display:"flex", gap:20, flexWrap:"wrap", alignItems:"flex-start" }}>
        <Card style={{ padding:"24px 32px", display:"flex", flexDirection:"column", alignItems:"center", gap:12 }}>
          <ScoreRing score={score.overall??0} size={120}/>
          <div style={{ textAlign:"center" }}>
            <div style={{ fontSize:11, color:"var(--text-2)" }}>Overall Compliance</div>
            {score.grade && <div style={{ fontFamily:"var(--font-mono)", fontSize:28, fontWeight:700,
              color:scoreColor(score.overall), marginTop:4 }}>{score.grade}</div>}
          </div>
        </Card>
        <div style={{ flex:1, display:"grid", gridTemplateColumns:"repeat(auto-fill,minmax(130px,1fr))", gap:1,
          background:"var(--border)", border:"1px solid var(--border)", borderRadius:"var(--radius)", overflow:"hidden" }}>
          {sections.map(s=>{
            const sc=data[s.key]?.score??null;
            return (
              <div key={s.key} style={{ background:"var(--surface)", padding:"16px 14px" }}>
                <div style={{ fontSize:18, fontFamily:"var(--font-mono)", fontWeight:700,
                  color:scoreColor(sc), marginBottom:4 }}>{sc!=null?`${sc}%`:"N/A"}</div>
                <div style={{ fontSize:11, color:"var(--text-2)" }}>{s.label}</div>
              </div>
            );
          })}
        </div>
      </div>
      <StatGrid stats={[
        {label:"Critical",value:summary.critical_findings??0,color:"var(--red)"},
        {label:"High",value:summary.high_findings??0,color:"var(--orange)"},
        {label:"Medium",value:summary.medium_findings??0,color:"var(--yellow)"},
        {label:"Low",value:summary.low_findings??0},
        {label:"Checks Passed",value:summary.passed_checks??0,color:"var(--green)"},
        {label:"Checks Failed",value:summary.failed_checks??0,color:"var(--red)"},
        {label:"Total Checks",value:summary.total_checks??0,accent:true},
      ]}/>
    </div>
  );
}

function ComplianceConfigRules({ data }) {
  const [tab,setTab]=useState("rules");
  if(!data) return <Empty message="No Config Rules data."/>;
  const tabs=[
    {id:"rules",      label:`Rules (${data.total_rules??0})`},
    {id:"violations", label:`Violations (${data.non_compliant_resources?.length??0})`},
    {id:"packs",      label:`Conformance Packs (${data.conformance_packs?.length??0})`},
  ];
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start" }}>
        <div>
          <h2 style={{ fontSize:16, fontWeight:700, marginBottom:4 }}>Config Rules</h2>
          <p style={{ fontSize:12, color:"var(--text-2)" }}>{data.compliant_count} compliant · {data.non_compliant_count} non-compliant</p>
        </div>
        <ScoreRing score={data.score??0} size={72} label="Score"/>
      </div>
      <StatGrid stats={[
        {label:"Total Rules",value:data.total_rules??0,accent:true},
        {label:"Compliant",value:data.compliant_count??0,color:"var(--green)"},
        {label:"Non-Compliant",value:data.non_compliant_count??0,color:"var(--red)"},
        {label:"Insufficient Data",value:data.insufficient_data_count??0,color:"var(--yellow)"},
      ]}/>
      <TabBar tabs={tabs} active={tab} setActive={setTab}/>
      {tab==="rules" && <TableComp maxHeight="55vh"
        columns={["Rule Name","Scope","Trigger","Compliance","Severity"]}
        rows={(data.rules||[]).map(r=>[
          <span style={{ fontSize:11 }}>{r.name}</span>,
          <span style={{ fontSize:11, color:"var(--text-2)" }}>{r.scope}</span>,
          <Badge type="neutral">{r.trigger||"—"}</Badge>,
          statusBadge(r.compliance),
          severityBadge(r.severity),
        ])}/>}
      {tab==="violations" && (data.non_compliant_resources?.length>0
        ? <TableComp maxHeight="55vh"
            columns={["Rule","Resource Type","Resource ID","Time"]}
            rows={data.non_compliant_resources.map(r=>[
              <span style={{ fontSize:11, color:"var(--red)" }}>{r.rule}</span>,
              <span style={{ fontSize:11 }}>{r.resource_type?.replace("AWS::","")}</span>,
              <Mono>{r.resource_id}</Mono>,
              <span style={{ fontSize:11, color:"var(--text-2)" }}>{r.result_time}</span>,
            ])}/>
        : <Empty message="No non-compliant resources found."/>)}
      {tab==="packs" && (data.conformance_packs?.length>0
        ? <TableComp columns={["Pack Name","Status","Score"]}
            rows={data.conformance_packs.map(p=>[
              <strong style={{ fontSize:12 }}>{p.name}</strong>,
              statusBadge(p.status),
              p.score!=null ? <span style={{ fontFamily:"var(--font-mono)", fontWeight:600, color:scoreColor(p.score) }}>{p.score}%</span> : "—",
            ])}/>
        : <Empty message="No conformance packs deployed."/>)}
    </div>
  );
}

function ComplianceSecurityHub({ data }) {
  const [tab,setTab]=useState("findings"), [sevFilter,setSevFilter]=useState("");
  if(!data) return <Empty message="No Security Hub data."/>;
  if(!data.enabled) return (
    <div style={{ padding:"20px", background:"var(--yellow-dim)", border:"1px solid var(--yellow-b)",
      borderRadius:"var(--radius)", fontSize:13, color:"var(--yellow)" }}>
      <div style={{ fontWeight:600, marginBottom:6 }}>⚠ Security Hub is not enabled in this region.</div>
      <div style={{ fontSize:12, opacity:0.8 }}>Enable via AWS Console or CLI to start collecting findings.</div>
    </div>
  );
  const sevCounts=data.severity_counts||{};
  const filtered=sevFilter?(data.findings||[]).filter(f=>f.severity===sevFilter):(data.findings||[]);
  const tabs=[
    {id:"findings",  label:`Findings (${data.total_findings??0})`},
    {id:"controls",  label:`Top Violations (${data.top_failed_controls?.length??0})`},
    {id:"standards", label:`Standards (${data.standards?.length??0})`},
  ];
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start" }}>
        <div>
          <h2 style={{ fontSize:16, fontWeight:700, marginBottom:4 }}>Security Hub</h2>
          <p style={{ fontSize:12, color:"var(--text-2)" }}>{data.total_findings} active findings</p>
        </div>
        <ScoreRing score={data.score??0} size={72} label="Security"/>
      </div>
      <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:1,
        background:"var(--border)", border:"1px solid var(--border)", borderRadius:"var(--radius)", overflow:"hidden" }}>
        {[
          {label:"Critical",val:sevCounts.CRITICAL??0,color:"var(--red)",key:"CRITICAL"},
          {label:"High",val:sevCounts.HIGH??0,color:"var(--orange)",key:"HIGH"},
          {label:"Medium",val:sevCounts.MEDIUM??0,color:"var(--yellow)",key:"MEDIUM"},
          {label:"Low",val:sevCounts.LOW??0,color:"var(--text-2)",key:"LOW"},
          {label:"Info",val:sevCounts.INFORMATIONAL??0,color:"var(--text-3)",key:"INFORMATIONAL"},
        ].map(({label,val,color,key})=>(
          <div key={key} onClick={()=>setSevFilter(sevFilter===key?"":key)}
            style={{ background:sevFilter===key?"var(--surface-3)":"var(--surface)", padding:"12px 14px", cursor:"pointer" }}>
            <div style={{ fontSize:18, fontWeight:700, fontFamily:"var(--font-mono)", color }}>{val}</div>
            <div style={{ fontSize:11, color:"var(--text-2)", marginTop:2 }}>{label}</div>
          </div>
        ))}
      </div>
      <TabBar tabs={tabs} active={tab} setActive={setTab}/>
      {tab==="findings" && (filtered.length>0
        ? <TableComp maxHeight="55vh"
            columns={["Severity","Title","Resource","Product","Updated"]}
            rows={filtered.map(f=>[
              severityBadge(f.severity),
              <span style={{ fontSize:11 }}>{f.title?.slice(0,55)}{f.title?.length>55?"…":""}</span>,
              <Mono>{f.resource_id?.slice(0,28)}</Mono>,
              <span style={{ fontSize:11, color:"var(--text-2)" }}>{f.product}</span>,
              <span style={{ fontSize:11, color:"var(--text-2)" }}>{f.updated?.slice(0,10)}</span>,
            ])}/>
        : <Empty message="No findings for this filter."/>)}
      {tab==="controls" && (data.top_failed_controls?.length>0
        ? <Card>{data.top_failed_controls.map((c,i)=>{
            const maxCount=data.top_failed_controls[0]?.count||1;
            return (
              <div key={i} style={{ display:"flex", alignItems:"center", gap:12, padding:"9px 16px",
                borderBottom:i<data.top_failed_controls.length-1?"1px solid var(--border)":"none" }}>
                <div style={{ flex:1, minWidth:0 }}>
                  <div style={{ fontSize:12, marginBottom:4, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{c.title}</div>
                  <div style={{ height:3, background:"var(--surface-3)", borderRadius:2 }}>
                    <div style={{ width:`${(c.count/maxCount)*100}%`, height:"100%", background:"var(--red)", borderRadius:2 }}/>
                  </div>
                </div>
                <div style={{ display:"flex", alignItems:"center", gap:8, flexShrink:0 }}>
                  {severityBadge(c.severity)}
                  <span style={{ fontFamily:"var(--font-mono)", fontSize:12, fontWeight:600, color:"var(--red)" }}>{c.count}</span>
                </div>
              </div>
            );
          })}</Card>
        : <Empty message="No control violation data."/>)}
      {tab==="standards" && (data.standards?.length>0
        ? <TableComp columns={["Standard","Status"]}
            rows={data.standards.map(s=>[
              <strong style={{ fontSize:12 }}>{s.name}</strong>,
              <Badge type={s.status==="READY"?"green":"yellow"}>{s.status}</Badge>,
            ])}/>
        : <Empty message="No security standards subscribed."/>)}
    </div>
  );
}

function ComplianceIAM({ data }) {
  const [tab,setTab]=useState("checks");
  if(!data) return <Empty message="No IAM compliance data."/>;
  const tabs=[
    {id:"checks",   label:`Checks (${data.total_checks??0})`},
    {id:"users",    label:`Users (${data.users?.length??0})`},
    {id:"password", label:"Password Policy"},
    {id:"analyzer", label:`Access Analyzer (${data.access_analyzer?.length??0})`},
  ];
  const pp=data.password_policy||{};
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start" }}>
        <div>
          <h2 style={{ fontSize:16, fontWeight:700, marginBottom:4 }}>IAM Compliance</h2>
          <p style={{ fontSize:12, color:"var(--text-2)" }}>{data.passed} passed · {data.failed} failed</p>
        </div>
        <ScoreRing score={data.score??0} size={72} label="IAM"/>
      </div>
      {data.root_account && (
        <div style={{ display:"grid", gridTemplateColumns:"repeat(2,1fr)", gap:1,
          background:"var(--border)", border:"1px solid var(--border)", borderRadius:"var(--radius)", overflow:"hidden" }}>
          <div style={{ background:"var(--surface)", padding:"14px 16px" }}>
            <div style={{ fontSize:11, color:"var(--text-2)", marginBottom:6 }}>Root Account MFA</div>
            <Badge type={data.root_account.mfa_enabled?"green":"red"}>
              {data.root_account.mfa_enabled?"✓ Enabled":"✗ Not Enabled"}
            </Badge>
          </div>
          <div style={{ background:"var(--surface)", padding:"14px 16px" }}>
            <div style={{ fontSize:11, color:"var(--text-2)", marginBottom:6 }}>Root Access Keys</div>
            <Badge type={data.root_account.access_keys?"red":"green"}>
              {data.root_account.access_keys?"✗ Keys Exist — CRITICAL":"✓ No Access Keys"}
            </Badge>
          </div>
        </div>
      )}
      <TabBar tabs={tabs} active={tab} setActive={setTab}/>
      {tab==="checks"   && <CheckList checks={data.checks}/>}
      {tab==="users"    && (data.users?.length>0
        ? <TableComp maxHeight="55vh"
            columns={["Username","MFA","Password","Pwd Changed","Key1 Active","Key2 Active"]}
            rows={data.users.map(u=>[
              <strong style={{ fontSize:12 }}>{u.username}</strong>,
              <Badge type={u.mfa_active?"green":"red"}>{u.mfa_active?"✓ On":"✗ Off"}</Badge>,
              <Badge type={u.password_enabled==="true"?"accent":"neutral"}>{u.password_enabled}</Badge>,
              <span style={{ fontSize:11, color:"var(--text-2)" }}>{u.password_last_changed?.slice(0,10)}</span>,
              <Badge type={u.key1_active==="true"?"yellow":"neutral"}>{u.key1_active}</Badge>,
              <Badge type={u.key2_active==="true"?"yellow":"neutral"}>{u.key2_active}</Badge>,
            ])}/>
        : <Empty message="No IAM users found."/>)}
      {tab==="password" && (Object.keys(pp).length>0
        ? <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill,minmax(220px,1fr))", gap:1,
            background:"var(--border)", border:"1px solid var(--border)", borderRadius:"var(--radius)", overflow:"hidden" }}>
            {[
              ["Min Length",pp.MinimumPasswordLength??'—',pp.MinimumPasswordLength>=14],
              ["Uppercase Required",pp.RequireUppercaseCharacters?"Yes":"No",pp.RequireUppercaseCharacters],
              ["Symbols Required",pp.RequireSymbols?"Yes":"No",pp.RequireSymbols],
              ["Max Age",pp.MaxPasswordAge?`${pp.MaxPasswordAge} days`:"Not set",pp.MaxPasswordAge<=90],
              ["Reuse Prevention",pp.PasswordReusePrevention??'Not set',pp.PasswordReusePrevention>=24],
            ].map(([label,val,ok])=>(
              <div key={label} style={{ background:"var(--surface)", padding:"12px 16px",
                display:"flex", justifyContent:"space-between", alignItems:"center" }}>
                <div>
                  <div style={{ fontSize:11, color:"var(--text-2)", marginBottom:3 }}>{label}</div>
                  <div style={{ fontFamily:"var(--font-mono)", fontSize:13, fontWeight:500 }}>{String(val)}</div>
                </div>
                <span style={{ fontSize:16, color:ok?"var(--green)":"var(--red)" }}>{ok?"✓":"✗"}</span>
              </div>
            ))}
          </div>
        : <Empty message="No password policy configured."/>)}
      {tab==="analyzer" && (data.access_analyzer?.length>0
        ? <TableComp columns={["Finding ID","Type","Resource","Status","Created"]}
            rows={data.access_analyzer.map(f=>[
              <Mono>{f.id}</Mono>,
              <Badge type="orange">{f.type}</Badge>,
              <span style={{ fontSize:11 }}>{f.resource}</span>,
              <Badge type={f.status==="ACTIVE"?"red":"neutral"}>{f.status}</Badge>,
              <span style={{ fontSize:11, color:"var(--text-2)" }}>{f.created?.slice(0,10)}</span>,
            ])}/>
        : <Empty message="No Access Analyzer findings."/>)}
    </div>
  );
}

function ComplianceCloudTrail({ data }) {
  if(!data) return <Empty message="No CloudTrail data."/>;
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start" }}>
        <div>
          <h2 style={{ fontSize:16, fontWeight:700, marginBottom:4 }}>CloudTrail</h2>
          <p style={{ fontSize:12, color:"var(--text-2)" }}>{data.trails?.length??0} trails · {data.passed} passed · {data.failed} failed</p>
        </div>
        <ScoreRing score={data.score??0} size={72} label="Trail"/>
      </div>
      <CheckList checks={data.checks}/>
      {data.trails?.length>0 && (
        <div>
          <SectionTitle>Trail Details</SectionTitle>
          <TableComp columns={["Name","Multi-Region","Log Validation","Logging","Mgmt Events","S3 Bucket"]}
            rows={data.trails.map(t=>[
              <strong style={{ fontSize:12 }}>{t.name}</strong>,
              <Badge type={t.multi_region?"green":"red"}>{t.multi_region?"✓":"✗"}</Badge>,
              <Badge type={t.log_validation?"green":"red"}>{t.log_validation?"✓":"✗"}</Badge>,
              <Badge type={t.logging?"green":"red"}>{t.logging?"Active":"Stopped"}</Badge>,
              <Badge type={t.mgmt_events?"green":"red"}>{t.mgmt_events?"✓":"✗"}</Badge>,
              <Mono>{t.s3_bucket?.slice(0,24)}</Mono>,
            ])}/>
        </div>
      )}
    </div>
  );
}

function ComplianceGuardDuty({ data }) {
  if(!data) return <Empty message="No GuardDuty data."/>;
  if(!data.enabled) return (
    <div style={{ padding:"20px", background:"var(--yellow-dim)", border:"1px solid var(--yellow-b)",
      borderRadius:"var(--radius)", fontSize:13, color:"var(--yellow)" }}>
      <div style={{ fontWeight:600, marginBottom:6 }}>⚠ GuardDuty is not enabled.</div>
    </div>
  );
  const sev=data.severity_counts||{};
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start" }}>
        <div>
          <h2 style={{ fontSize:16, fontWeight:700, marginBottom:4 }}>GuardDuty</h2>
          <p style={{ fontSize:12, color:"var(--text-2)" }}>{data.total_findings} active findings</p>
        </div>
        <ScoreRing score={data.score??0} size={72} label="Threat"/>
      </div>
      <StatGrid stats={[
        {label:"High",value:sev.HIGH??0,color:"var(--red)"},
        {label:"Medium",value:sev.MEDIUM??0,color:"var(--yellow)"},
        {label:"Low",value:sev.LOW??0},
      ]}/>
      {data.total_findings===0
        ? <div style={{ padding:"28px", textAlign:"center", border:"1px solid var(--green-b)",
            borderRadius:"var(--radius)", background:"var(--green-dim)", color:"var(--green)", fontSize:13 }}>
            ✓ No active threats detected.
          </div>
        : <TableComp maxHeight="55vh"
            columns={["Severity","Type","Title","Resource","Count","Updated"]}
            rows={(data.findings||[]).map(f=>[
              severityBadge(f.severity),
              <span style={{ fontSize:10, color:"var(--text-2)", fontFamily:"var(--font-mono)" }}>{f.type?.split("/").pop()}</span>,
              <span style={{ fontSize:11 }}>{f.title?.slice(0,45)}{f.title?.length>45?"…":""}</span>,
              <Badge type="neutral">{f.resource_type}</Badge>,
              <span style={{ fontFamily:"var(--font-mono)", fontSize:12, fontWeight:600, color:"var(--orange)" }}>{f.count}</span>,
              <span style={{ fontSize:11, color:"var(--text-2)" }}>{f.updated?.slice(0,10)}</span>,
            ])}/>}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE 3 — RISK
// ═══════════════════════════════════════════════════════════════════════════════
function RiskDashboard({ data, meta }) {
  const [active,setActive]=useState("overview");
  const summary=data.summary||{}, sev=summary.severity_counts||{};
  const nav=[
    {id:"overview",   label:"Risk Overview",  icon:"★"},
    {id:"findings",   label:"All Findings",   icon:"⚡", badge:summary.total_findings??null, badgeColor:summary.total_findings>0?"var(--orange)":"var(--green)"},
    {id:"inspector",  label:"Inspector",       icon:"◈", badge:data.inspector?.enabled===false?"OFF":(data.inspector?.total_findings??null), badgeColor:data.inspector?.enabled===false?"var(--text-3)":"var(--purple)"},
    {id:"macie",      label:"Macie",           icon:"◎", badge:data.macie?.enabled===false?"OFF":(data.macie?.total_findings??null), badgeColor:data.macie?.enabled===false?"var(--text-3)":"var(--cyan)"},
    {id:"guardduty",  label:"GuardDuty",       icon:"◆", badge:data.guardduty?.enabled===false?"OFF":(data.guardduty?.total_findings??null), badgeColor:data.guardduty?.enabled===false?"var(--text-3)":"var(--orange)"},
    {id:"health",     label:"AWS Health",      icon:"♡", badge:data.health?.open_events??null, badgeColor:"var(--yellow)"},
    {id:"cloudwatch", label:"CloudWatch",      icon:"◇", badge:data.cloudwatch?.in_alarm??null, badgeColor:data.cloudwatch?.in_alarm>0?"var(--red)":"var(--green)"},
  ];
  return (
    <SidebarLayout nav={nav} activeNav={active} setActiveNav={setActive}
      accentColor="var(--orange)" meta={meta}
      topInfo={[["Account",data.identity?.account_id],["Region",data.region],
        ["Risk Level",data.risk_score?.level||"—"],["Total Findings",summary.total_findings??0]]}>
      <div key={active}>
        {active==="overview"   && <RiskOverview data={data} meta={meta}/>}
        {active==="findings"   && <RiskAllFindings data={data}/>}
        {active==="inspector"  && <RiskInspector data={data.inspector}/>}
        {active==="macie"      && <RiskMacie data={data.macie}/>}
        {active==="guardduty"  && <RiskGuardDuty data={data.guardduty}/>}
        {active==="health"     && <RiskHealth data={data.health}/>}
        {active==="cloudwatch" && <RiskCloudWatch data={data.cloudwatch}/>}
      </div>
    </SidebarLayout>
  );
}

function RiskOverview({ data, meta }) {
  const risk=data.risk_score||{}, summary=data.summary||{}, sev=summary.severity_counts||{},
    src=summary.source_counts||{}, costs=data.costs||{}, health=data.health||{}, cw=data.cloudwatch||{};
  const topRisks=summary.top_risks||[];
  const maxSrc=Math.max(...Object.values(src),1);
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:24 }}>
      <div>
        <h2 style={{ fontSize:16, fontWeight:700, marginBottom:4 }}>Risk Overview</h2>
        <p style={{ fontSize:12, color:"var(--text-2)" }}>{meta?.timestamp} · {data.region} · {data.scan_time}</p>
      </div>
      <div style={{ display:"flex", gap:16, flexWrap:"wrap" }}>
        <Card style={{ padding:"24px 28px", display:"flex", flexDirection:"column", alignItems:"center", gap:8 }}>
          <RiskGauge score={risk.score??0} level={risk.level??"LOW"}/>
        </Card>
        <Card style={{ flex:1, padding:"16px 20px", minWidth:180 }}>
          <SectionTitle>By Severity</SectionTitle>
          {[{l:"Critical",v:sev.CRITICAL||0,c:"var(--red)"},{l:"High",v:sev.HIGH||0,c:"var(--orange)"},
            {l:"Medium",v:sev.MEDIUM||0,c:"var(--yellow)"},{l:"Low",v:sev.LOW||0,c:"var(--text-2)"}].map(({l,v,c})=>(
            <div key={l} style={{ marginBottom:12 }}>
              <div style={{ fontSize:11, color:"var(--text-2)", marginBottom:4 }}>{l}</div>
              <MiniBar value={v} max={summary.total_findings||1} color={c}/>
            </div>
          ))}
        </Card>
        <Card style={{ flex:1, padding:"16px 20px", minWidth:180 }}>
          <SectionTitle>By Source</SectionTitle>
          {Object.entries(src).sort((a,b)=>b[1]-a[1]).map(([name,count])=>(
            <div key={name} style={{ marginBottom:12 }}>
              <div style={{ fontSize:11, color:"var(--text-2)", marginBottom:4 }}>{name}</div>
              <MiniBar value={count} max={maxSrc} color="var(--orange)"/>
            </div>
          ))}
          {Object.keys(src).length===0 && <span style={{ fontSize:12, color:"var(--text-3)" }}>No findings</span>}
        </Card>
      </div>
      <StatGrid stats={[
        {label:"Total Findings",value:summary.total_findings??0,color:"var(--orange)"},
        {label:"Critical",value:sev.CRITICAL??0,color:"var(--red)"},
        {label:"High",value:sev.HIGH??0,color:"var(--orange)"},
        {label:"Open Health Events",value:health.open_events??0,color:"var(--yellow)"},
        {label:"Alarms Firing",value:cw.in_alarm??0,color:"var(--red)"},
        {label:"MTD Cost",value:costs.total?`$${costs.total}`:"—",color:"var(--cyan)"},
        {label:"Forecast",value:costs.forecast?`$${costs.forecast}`:"—"},
      ]}/>
      {topRisks.length>0 && (
        <div>
          <SectionTitle>Top 5 Risks — Immediate Attention</SectionTitle>
          <Card>{topRisks.map((f,i)=>(
            <div key={i} style={{ display:"flex", alignItems:"flex-start", gap:12, padding:"12px 16px",
              borderBottom:i<topRisks.length-1?"1px solid var(--border)":"none" }}>
              <div style={{ width:24, height:24, borderRadius:"50%", background:"var(--red-dim)",
                border:"1px solid var(--red-b)", display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0 }}>
                <span style={{ fontSize:11, fontWeight:700, color:"var(--red)" }}>{i+1}</span>
              </div>
              <div style={{ flex:1, minWidth:0 }}>
                <div style={{ fontSize:12, fontWeight:500, marginBottom:4,
                  overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{f.title}</div>
                <div style={{ display:"flex", gap:6 }}>{severityBadge(f.severity)}{sourceBadge(f.source)}</div>
              </div>
            </div>
          ))}</Card>
        </div>
      )}
    </div>
  );
}

function RiskAllFindings({ data }) {
  const [search,setSearch]=useState(""), [sevF,setSevF]=useState(""), [srcF,setSrcF]=useState(""), [page,setPage]=useState(1);
  const PAGE=50;
  const findings=data.unified_findings||[];
  const sources=[...new Set(findings.map(f=>f.source))];
  const filtered=useMemo(()=>findings.filter(f=>{
    const q=search.toLowerCase();
    return (!q||[f.title,f.resource,f.source].some(v=>v?.toLowerCase().includes(q)))
      && (!sevF||f.severity===sevF) && (!srcF||f.source===srcF);
  }),[findings,search,sevF,srcF]);
  const totalPages=Math.ceil(filtered.length/PAGE), paged=filtered.slice((page-1)*PAGE,page*PAGE);
  const SS={ background:"var(--surface)", border:"1px solid var(--border)", borderRadius:"var(--radius-sm)",
    padding:"7px 10px", fontSize:12, color:"var(--text-1)", fontFamily:"var(--font-sans)", outline:"none", cursor:"pointer" };
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
      <div>
        <h2 style={{ fontSize:16, fontWeight:700, marginBottom:4 }}>All Findings</h2>
        <p style={{ fontSize:12, color:"var(--text-2)" }}>{findings.length} total · {filtered.length} shown</p>
      </div>
      <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
        <input value={search} onChange={e=>{setSearch(e.target.value);setPage(1);}} placeholder="Search title, resource, source…"
          style={{ flex:1, minWidth:200, ...SS, padding:"7px 12px" }}/>
        <select value={sevF} onChange={e=>{setSevF(e.target.value);setPage(1);}} style={SS}>
          <option value="">All Severities</option>
          {["CRITICAL","HIGH","MEDIUM","LOW"].map(s=><option key={s} value={s}>{s}</option>)}
        </select>
        <select value={srcF} onChange={e=>{setSrcF(e.target.value);setPage(1);}} style={SS}>
          <option value="">All Sources</option>
          {sources.map(s=><option key={s} value={s}>{s}</option>)}
        </select>
        {(search||sevF||srcF) && <button onClick={()=>{setSearch("");setSevF("");setSrcF("");setPage(1);}} style={{ ...SS, color:"var(--text-2)" }}>Clear</button>}
      </div>
      {paged.length===0 ? <Empty message="No findings match."/> : (
        <TableComp maxHeight="calc(100vh - 330px)"
          columns={["#","Severity","Source","Title","Resource","Score","Created"]}
          rows={paged.map((f,ri)=>[
            <span style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--text-3)" }}>{(page-1)*PAGE+ri+1}</span>,
            severityBadge(f.severity),
            sourceBadge(f.source),
            <span style={{ fontSize:11 }}>{f.title?.slice(0,50)}{f.title?.length>50?"…":""}</span>,
            <Mono>{f.resource?.split("/").pop()?.slice(0,22)}</Mono>,
            <span style={{ fontFamily:"var(--font-mono)", fontSize:12, fontWeight:600, color:"var(--orange)" }}>{f.score}</span>,
            <span style={{ fontSize:11, color:"var(--text-2)" }}>{f.created?.slice(0,10)}</span>,
          ])}/>
      )}
      {totalPages>1 && (
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
          <span style={{ fontSize:12, color:"var(--text-2)" }}>Page {page} of {totalPages}</span>
          <div style={{ display:"flex", gap:6 }}>
            <PagBtn disabled={page<=1} onClick={()=>setPage(p=>p-1)}>←</PagBtn>
            {Array.from({length:Math.min(5,totalPages)},(_,i)=>{
              const pg=Math.max(1,Math.min(page-2,totalPages-4))+i;
              return pg<=totalPages?<PagBtn key={pg} active={pg===page} onClick={()=>setPage(pg)}>{pg}</PagBtn>:null;
            })}
            <PagBtn disabled={page>=totalPages} onClick={()=>setPage(p=>p+1)}>→</PagBtn>
          </div>
        </div>
      )}
    </div>
  );
}

function RiskInspector({ data }) {
  const [tab,setTab]=useState("findings");
  if(!data) return <Empty message="No Inspector data."/>;
  if(!data.enabled) return (
    <div style={{ padding:"20px", background:"var(--yellow-dim)", border:"1px solid var(--yellow-b)",
      borderRadius:"var(--radius)", fontSize:13, color:"var(--yellow)" }}>
      <div style={{ fontWeight:600, marginBottom:6 }}>⚠ Amazon Inspector v2 not enabled.</div>
      <div style={{ fontSize:12, opacity:0.8 }}>Enable it in the AWS Console or via CLI to scan EC2, Lambda, and ECR for CVEs.</div>
      {data.errors?.map((e,i)=><div key={i} style={{ marginTop:8, fontSize:11, opacity:0.7 }}>{e}</div>)}
    </div>
  );
  const sev=data.severity_counts||{}, cov=data.coverage||{};
  const tabs=[{id:"findings",label:`Findings (${data.total_findings??0})`},{id:"coverage",label:"Coverage"}];
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start" }}>
        <div>
          <h2 style={{ fontSize:16, fontWeight:700, marginBottom:4 }}>Amazon Inspector v2</h2>
          <p style={{ fontSize:12, color:"var(--text-2)" }}>Vulnerability scanning · EC2, Lambda, ECR</p>
        </div>
        <Badge type="purple">ENABLED</Badge>
      </div>
      <StatGrid stats={[
        {label:"Critical",value:sev.CRITICAL??0,color:"var(--red)"},
        {label:"High",value:sev.HIGH??0,color:"var(--orange)"},
        {label:"Medium",value:sev.MEDIUM??0,color:"var(--yellow)"},
        {label:"Low",value:sev.LOW??0},
      ]}/>
      <TabBar tabs={tabs} active={tab} setActive={setTab}/>
      {tab==="findings" && (data.findings?.length>0
        ? <TableComp maxHeight="55vh"
            columns={["Severity","Score","CVE","Title","Resource","Fix Available"]}
            rows={data.findings.map(f=>[
              severityBadge(f.severity),
              <span style={{ fontFamily:"var(--font-mono)", fontSize:12, fontWeight:600, color:"var(--orange)" }}>{f.score}</span>,
              <Mono>{f.cve}</Mono>,
              <span style={{ fontSize:11 }}>{f.title?.slice(0,40)}{f.title?.length>40?"…":""}</span>,
              <Mono>{f.resource_id?.slice(0,22)}</Mono>,
              <Badge type={f.fix_available?"green":"neutral"}>{f.fix_available?"✓ Fix Available":"No Fix"}</Badge>,
            ])}/>
        : <div style={{ padding:"28px", textAlign:"center", border:"1px solid var(--green-b)",
            borderRadius:"var(--radius)", background:"var(--green-dim)", color:"var(--green)", fontSize:13 }}>
            ✓ No Inspector findings.
          </div>)}
      {tab==="coverage" && (
        <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:1,
          background:"var(--border)", border:"1px solid var(--border)", borderRadius:"var(--radius)", overflow:"hidden" }}>
          {[["EC2",cov.ec2],["Lambda",cov.lambda],["ECR",cov.ecr]].map(([label,val])=>(
            <div key={label} style={{ background:"var(--surface)", padding:"20px 16px", textAlign:"center" }}>
              <div style={{ marginBottom:8 }}><Badge type={val==="ENABLED"?"green":"red"}>{val||"DISABLED"}</Badge></div>
              <div style={{ fontSize:12, color:"var(--text-2)" }}>{label} Scanning</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function RiskMacie({ data }) {
  if(!data) return <Empty message="No Macie data."/>;
  if(!data.enabled) return (
    <div style={{ padding:"20px", background:"var(--yellow-dim)", border:"1px solid var(--yellow-b)",
      borderRadius:"var(--radius)", fontSize:13, color:"var(--yellow)" }}>
      <div style={{ fontWeight:600, marginBottom:6 }}>⚠ Amazon Macie not enabled.</div>
      {data.errors?.map((e,i)=><div key={i} style={{ marginTop:6, fontSize:11, opacity:0.7 }}>{e}</div>)}
    </div>
  );
  const sev=data.severity_counts||{}, cats=data.data_categories||{};
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start" }}>
        <div>
          <h2 style={{ fontSize:16, fontWeight:700, marginBottom:4 }}>Amazon Macie</h2>
          <p style={{ fontSize:12, color:"var(--text-2)" }}>Sensitive data discovery · {data.total_findings} findings</p>
        </div>
        <Badge type="cyan">ENABLED</Badge>
      </div>
      <StatGrid stats={[
        {label:"Critical",value:sev.CRITICAL??0,color:"var(--red)"},
        {label:"High",value:sev.HIGH??0,color:"var(--orange)"},
        {label:"Medium",value:sev.MEDIUM??0,color:"var(--yellow)"},
        {label:"Low",value:sev.LOW??0},
      ]}/>
      {Object.keys(cats).length>0 && (
        <div>
          <SectionTitle>Sensitive Data Categories Found</SectionTitle>
          <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
            {Object.entries(cats).map(([cat,count])=>(
              <div key={cat} style={{ padding:"8px 14px", background:"var(--red-dim)",
                border:"1px solid var(--red-b)", borderRadius:"var(--radius-sm)" }}>
                <div style={{ fontSize:14, fontWeight:600, fontFamily:"var(--font-mono)", color:"var(--red)" }}>{count}</div>
                <div style={{ fontSize:11, color:"var(--text-2)", marginTop:2 }}>{cat}</div>
              </div>
            ))}
          </div>
        </div>
      )}
      {data.findings?.length>0
        ? <TableComp maxHeight="50vh"
            columns={["Severity","Type","S3 Bucket","Data Categories","Count"]}
            rows={data.findings.map(f=>[
              severityBadge(f.severity),
              <span style={{ fontSize:11, color:"var(--text-2)" }}>{f.type?.split(":").pop()}</span>,
              <strong style={{ fontSize:12 }}>{f.resource}</strong>,
              <span style={{ fontSize:11, color:"var(--yellow)" }}>{f.categories}</span>,
              <span style={{ fontFamily:"var(--font-mono)", fontSize:12, fontWeight:600 }}>{f.count}</span>,
            ])}/>
        : <div style={{ padding:"28px", textAlign:"center", border:"1px solid var(--green-b)",
            borderRadius:"var(--radius)", background:"var(--green-dim)", color:"var(--green)", fontSize:13 }}>
            ✓ No Macie findings.
          </div>}
    </div>
  );
}

function RiskGuardDuty({ data }) {
  if(!data) return <Empty message="No GuardDuty data."/>;
  if(!data.enabled) return (
    <div style={{ padding:"20px", background:"var(--yellow-dim)", border:"1px solid var(--yellow-b)",
      borderRadius:"var(--radius)", fontSize:13, color:"var(--yellow)" }}>
      <div style={{ fontWeight:600, marginBottom:6 }}>⚠ GuardDuty not enabled.</div>
    </div>
  );
  const sev=data.severity_counts||{};
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start" }}>
        <div>
          <h2 style={{ fontSize:16, fontWeight:700, marginBottom:4 }}>Amazon GuardDuty</h2>
          <p style={{ fontSize:12, color:"var(--text-2)" }}>Threat detection · {data.total_findings} findings</p>
        </div>
        <Badge type="orange">ENABLED</Badge>
      </div>
      <StatGrid stats={[{label:"High",value:sev.HIGH??0,color:"var(--red)"},{label:"Medium",value:sev.MEDIUM??0,color:"var(--yellow)"},{label:"Low",value:sev.LOW??0}]}/>
      {data.total_findings===0
        ? <div style={{ padding:"28px", textAlign:"center", border:"1px solid var(--green-b)",
            borderRadius:"var(--radius)", background:"var(--green-dim)", color:"var(--green)", fontSize:13 }}>
            ✓ No active threats detected.
          </div>
        : <TableComp maxHeight="55vh"
            columns={["Severity","Type","Title","Resource","Count","Created"]}
            rows={(data.findings||[]).map(f=>[
              severityBadge(f.severity),
              <span style={{ fontSize:10, color:"var(--text-2)", fontFamily:"var(--font-mono)" }}>{f.type?.split("/").pop()}</span>,
              <span style={{ fontSize:11 }}>{f.title?.slice(0,45)}{f.title?.length>45?"…":""}</span>,
              <Badge type="neutral">{f.resource_type}</Badge>,
              <span style={{ fontFamily:"var(--font-mono)", fontSize:12, fontWeight:600, color:"var(--orange)" }}>{f.count}</span>,
              <span style={{ fontSize:11, color:"var(--text-2)" }}>{f.created?.slice(0,10)}</span>,
            ])}/>}
    </div>
  );
}

function RiskHealth({ data }) {
  if(!data) return <Empty message="No AWS Health data."/>;
  const byService=data.by_service||{};
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
      <div>
        <h2 style={{ fontSize:16, fontWeight:700, marginBottom:4 }}>AWS Health</h2>
        <p style={{ fontSize:12, color:"var(--text-2)" }}>Active and upcoming events affecting your account</p>
      </div>
      {data.errors?.map((e,i)=>(
        <div key={i} style={{ padding:"10px 14px", background:"var(--yellow-dim)", border:"1px solid var(--yellow-b)",
          borderRadius:"var(--radius-sm)", fontSize:12, color:"var(--yellow)" }}>ℹ {e}</div>
      ))}
      <StatGrid stats={[
        {label:"Total Events",value:data.total_events??0,accent:true},
        {label:"Open Events",value:data.open_events??0,color:data.open_events>0?"var(--red)":undefined},
        {label:"Services Affected",value:Object.keys(byService).length},
      ]}/>
      {data.events?.length>0
        ? <TableComp maxHeight="55vh"
            columns={["Service","Category","Status","Region","Start","End"]}
            rows={data.events.map(ev=>[
              <strong style={{ fontSize:12 }}>{ev.service}</strong>,
              <Badge type={ev.category==="issue"?"red":ev.category==="scheduledChange"?"yellow":"neutral"}>{ev.category}</Badge>,
              <Badge type={ev.status==="open"?"red":ev.status==="upcoming"?"yellow":"green"}>{ev.status}</Badge>,
              <Mono>{ev.region}</Mono>,
              <span style={{ fontSize:11, color:"var(--text-2)" }}>{ev.start?.slice(0,10)}</span>,
              <span style={{ fontSize:11, color:"var(--text-2)" }}>{ev.end?.slice(0,10)||"—"}</span>,
            ])}/>
        : <div style={{ padding:"28px", textAlign:"center", border:"1px solid var(--green-b)",
            borderRadius:"var(--radius)", background:"var(--green-dim)", color:"var(--green)", fontSize:13 }}>
            ✓ No active AWS Health events.
          </div>}
    </div>
  );
}

function RiskCloudWatch({ data }) {
  if(!data) return <Empty message="No CloudWatch data."/>;
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
      <div>
        <h2 style={{ fontSize:16, fontWeight:700, marginBottom:4 }}>CloudWatch Alarms</h2>
        <p style={{ fontSize:12, color:"var(--text-2)" }}>{data.total_alarms} total · {data.in_alarm} firing · {data.ok} OK</p>
      </div>
      <StatGrid stats={[
        {label:"In ALARM",value:data.in_alarm??0,color:"var(--red)"},
        {label:"Insufficient Data",value:data.insufficient??0,color:"var(--yellow)"},
        {label:"OK",value:data.ok??0,color:"var(--green)"},
        {label:"Total Alarms",value:data.total_alarms??0},
      ]}/>
      {data.alarms?.length>0
        ? <TableComp maxHeight="55vh"
            columns={["State","Alarm Name","Metric","Namespace","Threshold","Actions"]}
            rows={data.alarms.map(a=>[
              <Badge type={a.state==="ALARM"?"red":a.state==="OK"?"green":"yellow"}>
                {a.state==="ALARM"?"🔴 ALARM":a.state==="OK"?"✓ OK":a.state}
              </Badge>,
              <strong style={{ fontSize:12 }}>{a.name}</strong>,
              <span style={{ fontSize:11, color:"var(--text-2)" }}>{a.metric}</span>,
              <span style={{ fontSize:11, color:"var(--text-3)" }}>{a.namespace}</span>,
              <Mono>{a.threshold}</Mono>,
              <Badge type={a.actions>0?"green":"neutral"}>{a.actions} action{a.actions!==1?"s":""}</Badge>,
            ])}/>
        : <div style={{ padding:"28px", textAlign:"center", border:"1px solid var(--green-b)",
            borderRadius:"var(--radius)", background:"var(--green-dim)", color:"var(--green)", fontSize:13 }}>
            ✓ No CloudWatch alarms firing.
          </div>}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE 4 — MANUAL REMEDIATION (Phase 4)
// ═══════════════════════════════════════════════════════════════════════════════

function RemediationDashboard({ data, meta, onRemediate, auditLog, onRescan }) {
  const [active, setActive] = useState("overview");
  const summary  = data.summary || {};
  const sev      = summary.severity_counts || {};
  const byCat    = summary.by_category    || {};

  const NAV = [
    { id: "overview", label: "Overview",        icon: "◈" },
    { id: "issues",   label: "Issues",          icon: "⚠" },
    { id: "audit",    label: "Audit Log",       icon: "📋" },
    { id: "catalog",  label: "Action Catalog",  icon: "◎" },
  ];

  return (
    <div style={{ display: "flex", minHeight: "calc(100vh - 100px)" }}>
      {/* Sidebar */}
      <aside style={{ width: 210, borderRight: "1px solid var(--border)", background: "var(--surface)", padding: "16px 0", position: "sticky", top: 100, height: "calc(100vh - 100px)", overflowY: "auto", flexShrink: 0 }}>
        <div style={{ padding: "0 16px 14px", borderBottom: "1px solid var(--border)", marginBottom: 8 }}>
          <div style={{ fontSize: 10, color: "var(--text-3)", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.06em" }}>Account</div>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, fontWeight: 500 }}>{data.identity?.account_id}</div>
          <div style={{ fontSize: 10, color: "var(--text-3)", marginTop: 4 }}>{data.region} · {meta?.duration}s</div>
        </div>
        <div style={{ padding: "8px 16px 14px", borderBottom: "1px solid var(--border)", marginBottom: 8 }}>
          <div style={{ fontSize: 10, color: "var(--text-3)", marginBottom: 8, textTransform: "uppercase", letterSpacing: "0.06em" }}>Issues Found</div>
          {[
            { label: "Critical", val: sev.CRITICAL || 0, color: "var(--red)" },
            { label: "High",     val: sev.HIGH     || 0, color: "var(--orange)" },
            { label: "Medium",   val: sev.MEDIUM   || 0, color: "var(--yellow)" },
            { label: "Low",      val: sev.LOW      || 0, color: "var(--text-2)" },
          ].map(({ label, val, color }) => (
            <div key={label} style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
              <span style={{ fontSize: 11, color: "var(--text-3)" }}>{label}</span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, fontWeight: 600, color }}>{val}</span>
            </div>
          ))}
        </div>
        {auditLog.length > 0 && (
          <div style={{ padding: "8px 16px 14px", borderBottom: "1px solid var(--border)", marginBottom: 8 }}>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <span style={{ fontSize: 11, color: "var(--text-3)" }}>Actions Taken</span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, fontWeight: 600, color: "var(--green)" }}>{auditLog.length}</span>
            </div>
          </div>
        )}
        {NAV.map(item => {
          const isActive = active === item.id;
          const badge = item.id === "issues"  ? summary.total_issues
                      : item.id === "audit"   ? auditLog.length
                      : null;
          return (
            <button key={item.id} onClick={() => setActive(item.id)} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", width: "100%", padding: "7px 16px", border: "none", borderLeft: isActive ? "2px solid var(--green)" : "2px solid transparent", background: isActive ? "var(--green-dim)" : "none", color: isActive ? "var(--green)" : "var(--text-2)", fontFamily: "var(--font-sans)", fontSize: 13, cursor: "pointer", fontWeight: isActive ? 500 : 400 }}>
              <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ fontSize: 12, opacity: 0.7 }}>{item.icon}</span>{item.label}
              </span>
              {badge != null && badge > 0 && (
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 600, color: item.id === "audit" ? "var(--green)" : "var(--red)" }}>{badge}</span>
              )}
            </button>
          );
        })}
        <div style={{ padding: "16px" }}>
          <button onClick={onRescan} style={{ width: "100%", padding: "7px 0", background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", fontSize: 12, color: "var(--text-2)", cursor: "pointer", fontFamily: "var(--font-sans)" }}>
            ↻ Re-scan
          </button>
        </div>
      </aside>
      <main style={{ flex: 1, minWidth: 0, overflowX: "hidden" }}>
        <div style={{ padding: "24px 28px", animation: "fadeIn 0.3s ease" }} key={active}>
          {active === "overview" && <RemediationOverview data={data} meta={meta} auditLog={auditLog} onNavigate={setActive} />}
          {active === "issues"   && <RemediationIssuesPanel issues={data.issues || []} catalog={data.catalog || {}} onRemediate={onRemediate} />}
          {active === "audit"    && <RemediationAuditLog log={auditLog} />}
          {active === "catalog"  && <RemediationActionCatalog catalog={data.catalog || {}} />}
        </div>
      </main>
    </div>
  );
}

function RemediationOverview({ data, meta, auditLog, onNavigate }) {
  const summary = data.summary || {};
  const sev     = summary.severity_counts || {};
  const byCat   = summary.by_category    || {};
  const issues  = data.issues || [];
  const criticalIssues = issues.filter(i => i.severity === "CRITICAL").slice(0, 5);
  const recentActions  = auditLog.slice(0, 5);
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
      <div>
        <h2 style={{ fontSize: 16, fontWeight: 600, letterSpacing: "-0.02em", marginBottom: 4 }}>Remediation Overview</h2>
        <p style={{ fontSize: 12, color: "var(--text-2)" }}>{meta?.timestamp} · {data.region} · Scanned in {meta?.duration}s · Account {data.identity?.account_id}</p>
      </div>
      <StatGrid stats={[
        { label: "Total Issues",  value: summary.total_issues ?? 0, color: "var(--orange)" },
        { label: "Critical",      value: sev.CRITICAL ?? 0,          color: "var(--red)" },
        { label: "High",          value: sev.HIGH     ?? 0,          color: "var(--orange)" },
        { label: "Medium",        value: sev.MEDIUM   ?? 0,          color: "var(--yellow)" },
        { label: "Actions Taken", value: auditLog.length,            color: "var(--green)" },
        { label: "Successful",    value: auditLog.filter(a => a.status === "SUCCESS").length, color: "var(--green)" },
        { label: "Failed",        value: auditLog.filter(a => a.status === "FAILED").length,  color: "var(--red)" },
      ]}/>
      {Object.keys(byCat).length > 0 && (
        <div>
          <SectionTitle>Issues by Category</SectionTitle>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {Object.entries(byCat).sort((a,b) => b[1]-a[1]).map(([cat, count]) => (
              <div key={cat} style={{ padding: "10px 16px", background: "var(--surface)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", minWidth: 100 }}>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 20, fontWeight: 700, color: "var(--orange)" }}>{count}</div>
                <div style={{ fontSize: 11, color: "var(--text-2)", marginTop: 3 }}>{cat}</div>
              </div>
            ))}
          </div>
        </div>
      )}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
        <div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
            <SectionTitle>Top Critical Issues</SectionTitle>
            <button onClick={() => onNavigate("issues")} style={{ fontSize: 11, color: "var(--accent)", background: "none", border: "none", cursor: "pointer", fontFamily: "var(--font-sans)" }}>View all →</button>
          </div>
          {criticalIssues.length > 0 ? (
            <Card>
              {criticalIssues.map((issue, i) => (
                <div key={i} style={{ padding: "10px 14px", borderBottom: i < criticalIssues.length - 1 ? "1px solid var(--border)" : "none" }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "flex-start", marginBottom: 4 }}>
                    {severityBadge(issue.severity)}
                    <Badge type="neutral">{issue.category}</Badge>
                  </div>
                  <div style={{ fontSize: 12, fontWeight: 500, marginTop: 4, marginBottom: 2 }}>{issue.title}</div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-2)" }}>{issue.resource_id}</div>
                </div>
              ))}
            </Card>
          ) : (
            <div style={{ padding: "24px", textAlign: "center", border: "1px solid var(--green-b)", borderRadius: "var(--radius)", background: "var(--green-dim)", color: "var(--green)", fontSize: 13 }}>✓ No critical issues found!</div>
          )}
        </div>
        <div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
            <SectionTitle>Recent Remediation Actions</SectionTitle>
            {recentActions.length > 0 && <button onClick={() => onNavigate("audit")} style={{ fontSize: 11, color: "var(--accent)", background: "none", border: "none", cursor: "pointer", fontFamily: "var(--font-sans)" }}>Full log →</button>}
          </div>
          {recentActions.length > 0 ? (
            <Card>
              {recentActions.map((action, i) => (
                <div key={i} style={{ padding: "10px 14px", borderBottom: i < recentActions.length - 1 ? "1px solid var(--border)" : "none" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
                    {statusBadge(action.status)}
                    <span style={{ fontSize: 10, color: "var(--text-3)" }}>{action.timestamp}</span>
                  </div>
                  <div style={{ fontSize: 12, fontWeight: 500, marginBottom: 2 }}>{action.action_label}</div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-2)" }}>{action.resource_id}</div>
                </div>
              ))}
            </Card>
          ) : (
            <div style={{ padding: "24px", textAlign: "center", border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--surface)", color: "var(--text-3)", fontSize: 13 }}>No actions taken yet. Go to Issues to start remediating.</div>
          )}
        </div>
      </div>
      {data.errors?.length > 0 && (
        <div>
          <SectionTitle>Scan Warnings</SectionTitle>
          <Card style={{ padding: 14 }}>
            {data.errors.map((e, i) => (
              <div key={i} style={{ fontSize: 11, color: "var(--yellow)", fontFamily: "var(--font-mono)", marginBottom: 4 }}>⚠ {e}</div>
            ))}
          </Card>
        </div>
      )}
    </div>
  );
}

function RemediationIssuesPanel({ issues, catalog, onRemediate }) {
  const [filter, setFilter]       = useState("");
  const [catFilter, setCatFilter] = useState("");
  const [executing, setExecuting] = useState({});
  const [results, setResults]     = useState({});
  const [expanded, setExpanded]   = useState(null);
  const [confirmPending, setConfirmPending] = useState(null);

  const categories = [...new Set(issues.map(i => i.category))];
  const filtered = issues.filter(i => {
    const q = filter.toLowerCase();
    return (!q || i.title?.toLowerCase().includes(q) || i.resource_id?.toLowerCase().includes(q))
        && (!catFilter || i.category === catFilter);
  });

  const handleAction = (issue, actionId) => {
    const action = catalog[actionId];
    if (!action?.reversible || action?.risk === "CRITICAL") {
      setConfirmPending({ issueId: issue.issue_id, actionId, resource: { resource_id: issue.resource_id, resource_type: issue.resource_type }, params: issue.params || {} });
      return;
    }
    doExecute(issue.issue_id, actionId, { resource_id: issue.resource_id, resource_type: issue.resource_type }, issue.params || {});
  };

  const doExecute = async (issueId, actionId, resource, params) => {
    setConfirmPending(null);
    const key = `${issueId}_${actionId}`;
    setExecuting(prev => ({ ...prev, [key]: true }));
    try {
      const result = await onRemediate(actionId, resource, params);
      setResults(prev => ({ ...prev, [key]: result }));
    } finally {
      setExecuting(prev => ({ ...prev, [key]: false }));
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {confirmPending && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center", padding: 24 }}>
          <div style={{ background: "var(--surface)", border: "1px solid var(--red-b)", borderRadius: "var(--radius)", padding: 28, maxWidth: 440, width: "100%" }}>
            <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 8, color: "var(--red)" }}>⚠ Confirm Action</div>
            <div style={{ fontSize: 13, color: "var(--text-2)", marginBottom: 16, lineHeight: 1.6 }}>
              You are about to execute: <strong style={{ color: "var(--text-1)" }}>{catalog[confirmPending.actionId]?.label}</strong>
            </div>
            <div style={{ padding: "10px 14px", background: "var(--surface-2)", borderRadius: "var(--radius-sm)", marginBottom: 16, fontSize: 12 }}>
              <div style={{ marginBottom: 4 }}><span style={{ color: "var(--text-3)" }}>Resource:</span> <Mono>{confirmPending.resource.resource_id}</Mono></div>
              <div><span style={{ color: "var(--text-3)" }}>Reversible:</span> <span style={{ color: catalog[confirmPending.actionId]?.reversible ? "var(--green)" : "var(--red)" }}>{catalog[confirmPending.actionId]?.reversible ? "Yes" : "No — Permanent"}</span></div>
            </div>
            {!catalog[confirmPending.actionId]?.reversible && (
              <div style={{ padding: "8px 12px", background: "var(--red-dim)", border: "1px solid var(--red-b)", borderRadius: 4, fontSize: 12, color: "var(--red)", marginBottom: 16 }}>
                This action is <strong>permanent and cannot be undone.</strong>
              </div>
            )}
            <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
              <button onClick={() => setConfirmPending(null)} style={{ padding: "8px 20px", background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", fontSize: 13, color: "var(--text-2)", cursor: "pointer", fontFamily: "var(--font-sans)" }}>Cancel</button>
              <button onClick={() => doExecute(confirmPending.issueId, confirmPending.actionId, confirmPending.resource, confirmPending.params)} style={{ padding: "8px 20px", background: "var(--red-dim)", border: "1px solid var(--red-b)", borderRadius: "var(--radius-sm)", fontSize: 13, color: "var(--red)", cursor: "pointer", fontFamily: "var(--font-sans)", fontWeight: 600 }}>Confirm & Execute</button>
            </div>
          </div>
        </div>
      )}
      <div>
        <h2 style={{ fontSize: 16, fontWeight: 600, letterSpacing: "-0.02em", marginBottom: 4 }}>Security Issues</h2>
        <p style={{ fontSize: 12, color: "var(--text-2)" }}>{issues.length} issues found · {filtered.length} shown</p>
      </div>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Search issues or resource IDs…"
          style={{ flex: 1, minWidth: 200, background: "var(--surface)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", padding: "7px 12px", fontSize: 12, color: "var(--text-1)", fontFamily: "var(--font-sans)", outline: "none" }} />
        <select value={catFilter} onChange={e => setCatFilter(e.target.value)}
          style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", padding: "7px 10px", fontSize: 12, color: "var(--text-1)", fontFamily: "var(--font-sans)", outline: "none", cursor: "pointer" }}>
          <option value="">All Categories</option>
          {categories.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        {(filter || catFilter) && (
          <button onClick={() => { setFilter(""); setCatFilter(""); }}
            style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", padding: "7px 12px", fontSize: 12, color: "var(--text-2)", cursor: "pointer", fontFamily: "var(--font-sans)" }}>Clear</button>
        )}
      </div>
      {filtered.length === 0 ? (
        <Empty message="No issues match your filter." />
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {filtered.map((issue) => {
            const isExpanded = expanded === issue.issue_id;
            const actionsKeys = issue.available_actions || [];
            const allDone = actionsKeys.length > 0 && actionsKeys.every(a => results[`${issue.issue_id}_${a}`]?.success === true);
            return (
              <div key={issue.issue_id} style={{ border: `1px solid ${allDone ? "var(--green-b)" : issue.severity === "CRITICAL" ? "var(--red-b)" : issue.severity === "HIGH" ? "var(--orange-b)" : "var(--border)"}`, borderRadius: "var(--radius)", background: allDone ? "var(--green-dim)" : "var(--surface)", overflow: "hidden" }}>
                <div style={{ padding: "12px 16px", display: "flex", alignItems: "flex-start", gap: 12, cursor: actionsKeys.length > 0 ? "pointer" : "default" }}
                  onClick={() => setExpanded(isExpanded ? null : issue.issue_id)}>
                  <div style={{ flexShrink: 0, marginTop: 2 }}>{severityBadge(issue.severity)}</div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginBottom: 4 }}>
                      <span style={{ fontWeight: 600, fontSize: 13 }}>{issue.title}</span>
                      {allDone && <Badge type="green">✓ Remediated</Badge>}
                    </div>
                    <div style={{ fontSize: 11, color: "var(--text-2)", marginBottom: 6 }}>{issue.description}</div>
                    <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                      <Badge type="neutral">{issue.category}</Badge>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-2)" }}>{issue.resource_id}</span>
                      {issue.region && issue.region !== "global" && <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-3)" }}>{issue.region}</span>}
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: 6, flexShrink: 0, flexWrap: "wrap", justifyContent: "flex-end", maxWidth: 320 }}>
                    {actionsKeys.map(actionId => {
                      const key = `${issue.issue_id}_${actionId}`;
                      const action = catalog[actionId] || {};
                      const isRunning = executing[key];
                      const result = results[key];
                      const done = result?.success === true;
                      const failed = result?.success === false;
                      const bgColor = done ? "var(--green-dim)" : failed ? "var(--red-dim)" : action.risk === "CRITICAL" ? "var(--red-dim)" : action.risk === "HIGH" ? "var(--orange-dim)" : "var(--surface-2)";
                      const borderColor = done ? "var(--green-b)" : failed ? "var(--red-b)" : action.risk === "CRITICAL" ? "var(--red-b)" : action.risk === "HIGH" ? "var(--orange-b)" : "var(--border)";
                      const textColor = done ? "var(--green)" : failed ? "var(--red)" : action.risk === "CRITICAL" ? "var(--red)" : action.risk === "HIGH" ? "var(--orange)" : "var(--text-2)";
                      return (
                        <button key={actionId} disabled={isRunning || done}
                          onClick={e => { e.stopPropagation(); handleAction(issue, actionId); }}
                          style={{ display: "flex", alignItems: "center", gap: 6, padding: "5px 12px", fontSize: 11, fontFamily: "var(--font-sans)", fontWeight: 500, background: bgColor, border: `1px solid ${borderColor}`, borderRadius: "var(--radius-sm)", color: textColor, cursor: isRunning || done ? "not-allowed" : "pointer", whiteSpace: "nowrap" }}>
                          {isRunning && <div style={{ width: 12, height: 12, border: "2px solid var(--border)", borderTop: "2px solid var(--accent)", borderRadius: "50%", animation: "spin 0.7s linear infinite" }} />}
                          {done ? "✓ Done" : failed ? "✗ Failed" : action.label || actionId}
                        </button>
                      );
                    })}
                    {issue.manual_steps && <span style={{ fontSize: 11, color: "var(--yellow)", padding: "5px 10px", border: "1px solid var(--yellow-b)", borderRadius: "var(--radius-sm)", background: "var(--yellow-dim)" }}>Manual Only</span>}
                  </div>
                </div>
                {isExpanded && (
                  <div style={{ padding: "0 16px 14px", borderTop: "1px solid var(--border)" }}>
                    {actionsKeys.some(a => results[`${issue.issue_id}_${a}`]) && (
                      <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 6 }}>
                        {actionsKeys.map(actionId => {
                          const result = results[`${issue.issue_id}_${actionId}`];
                          if (!result) return null;
                          return (
                            <div key={actionId} style={{ padding: "8px 12px", borderRadius: 4, background: result.success ? "var(--green-dim)" : "var(--red-dim)", border: `1px solid ${result.success ? "var(--green-b)" : "var(--red-b)"}`, fontSize: 12, color: result.success ? "var(--green)" : "var(--red)" }}>
                              {result.success ? "✓" : "✗"} {result.detail}
                            </div>
                          );
                        })}
                      </div>
                    )}
                    {issue.current_state && Object.keys(issue.current_state).length > 0 && (
                      <div style={{ marginTop: 12 }}>
                        <div style={{ fontSize: 10, color: "var(--text-3)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.07em" }}>Current State</div>
                        <pre style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--text-2)", background: "var(--surface-2)", padding: "8px 12px", borderRadius: 4, overflow: "auto", maxHeight: 120 }}>{JSON.stringify(issue.current_state, null, 2)}</pre>
                      </div>
                    )}
                    {issue.manual_steps && (
                      <div style={{ marginTop: 12, padding: "10px 14px", background: "var(--yellow-dim)", border: "1px solid var(--yellow-b)", borderRadius: 4, fontSize: 12, color: "var(--yellow)" }}>
                        <strong>Manual Steps Required:</strong> {issue.manual_steps}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function RemediationAuditLog({ log }) {
  const [expanded, setExpanded] = useState(null);
  if (!log?.length) {
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        <h2 style={{ fontSize: 16, fontWeight: 600 }}>Audit Log</h2>
        <Empty message="No remediation actions have been taken yet. Go to Issues and click an action button to get started." />
      </div>
    );
  }
  const successCount = log.filter(e => e.status === "SUCCESS").length;
  const failedCount  = log.filter(e => e.status === "FAILED").length;
  const skippedCount = log.filter(e => e.status === "SKIPPED").length;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <div>
        <h2 style={{ fontSize: 16, fontWeight: 600, letterSpacing: "-0.02em", marginBottom: 4 }}>Audit Log</h2>
        <p style={{ fontSize: 12, color: "var(--text-2)" }}>Full record of every remediation action taken in this session</p>
      </div>
      <StatGrid stats={[
        { label: "Total Actions", value: log.length,    color: "var(--accent)" },
        { label: "Successful",    value: successCount,  color: "var(--green)" },
        { label: "Failed",        value: failedCount,   color: "var(--red)" },
        { label: "Skipped",       value: skippedCount },
      ]}/>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {log.map((entry) => {
          const isExp = expanded === entry.id;
          const hasBefore = entry.before_state && Object.keys(entry.before_state).length > 0;
          const hasAfter  = entry.after_state  && Object.keys(entry.after_state).length > 0;
          return (
            <div key={entry.id} style={{ border: "1px solid var(--border)", borderRadius: "var(--radius)", background: "var(--surface)", overflow: "hidden" }}>
              <div style={{ padding: "12px 16px", display: "flex", alignItems: "flex-start", gap: 12, cursor: (hasBefore || hasAfter) ? "pointer" : "default" }}
                onClick={() => (hasBefore || hasAfter) ? setExpanded(isExp ? null : entry.id) : null}>
                <div style={{ flexShrink: 0, textAlign: "right", minWidth: 50 }}>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-3)" }}>#{entry.id}</div>
                  <div style={{ fontSize: 10, color: "var(--text-3)", marginTop: 2 }}>{entry.timestamp?.slice(11)}</div>
                </div>
                <div style={{ flexShrink: 0, marginTop: 1 }}>{statusBadge(entry.status)}</div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 12, fontWeight: 500, marginBottom: 3 }}>{entry.action_label}</div>
                  <div style={{ fontSize: 11, color: "var(--text-2)", marginBottom: 3 }}>{entry.detail}</div>
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                    <Mono>{entry.resource_id?.slice(0, 30)}</Mono>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-3)" }}>{entry.region}</span>
                  </div>
                </div>
                {(hasBefore || hasAfter) && <span style={{ fontSize: 12, color: "var(--text-3)", flexShrink: 0, marginTop: 2 }}>{isExp ? "▲" : "▼"}</span>}
              </div>
              {isExp && (hasBefore || hasAfter) && (
                <div style={{ borderTop: "1px solid var(--border)", padding: "12px 16px", display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                  {hasBefore && (
                    <div>
                      <div style={{ fontSize: 10, color: "var(--text-3)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.07em" }}>Before</div>
                      <pre style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--red)", background: "var(--red-dim)", padding: "8px 12px", borderRadius: 4, overflow: "auto", maxHeight: 100 }}>{JSON.stringify(entry.before_state, null, 2)}</pre>
                    </div>
                  )}
                  {hasAfter && (
                    <div>
                      <div style={{ fontSize: 10, color: "var(--text-3)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.07em" }}>After</div>
                      <pre style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--green)", background: "var(--green-dim)", padding: "8px 12px", borderRadius: 4, overflow: "auto", maxHeight: 100 }}>{JSON.stringify(entry.after_state, null, 2)}</pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function RemediationActionCatalog({ catalog }) {
  if (!catalog || Object.keys(catalog).length === 0) return <Empty message="No actions in catalog." />;
  const byCategory = {};
  Object.entries(catalog).forEach(([id, action]) => {
    const cat = action.category || "Other";
    if (!byCategory[cat]) byCategory[cat] = [];
    byCategory[cat].push({ id, ...action });
  });
  const catColors = { S3: "var(--accent)", Network: "var(--orange)", IAM: "var(--purple)", EC2: "var(--yellow)", GuardDuty: "var(--red)" };
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
      <div>
        <h2 style={{ fontSize: 16, fontWeight: 600, letterSpacing: "-0.02em", marginBottom: 4 }}>Action Catalog</h2>
        <p style={{ fontSize: 12, color: "var(--text-2)" }}>{Object.keys(catalog).length} remediation actions available across {Object.keys(byCategory).length} categories</p>
      </div>
      {Object.entries(byCategory).map(([category, actions]) => (
        <div key={category}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
            <div style={{ width: 3, height: 18, background: catColors[category] || "var(--accent)", borderRadius: 2 }} />
            <SectionTitle>{category}</SectionTitle>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))", gap: 10 }}>
            {actions.map(action => (
              <div key={action.id} style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "14px 16px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8 }}>
                  <div style={{ fontWeight: 600, fontSize: 13, flex: 1, marginRight: 8 }}>{action.label}</div>
                  {severityBadge(action.risk)}
                </div>
                <div style={{ fontSize: 12, color: "var(--text-2)", marginBottom: 10, lineHeight: 1.5 }}>{action.description}</div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  <Badge type={action.reversible ? "green" : "red"}>{action.reversible ? "↩ Reversible" : "⚠ Permanent"}</Badge>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, padding: "2px 8px", borderRadius: 10, background: "var(--surface-3)", color: "var(--text-3)", border: "1px solid var(--border)" }}>{action.id}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// MODULE 5 — AUTO REMEDIATION (Phase 5) — embedded components
// ═══════════════════════════════════════════════════════════════════════════════

function Toggle({ enabled, onChange }) {
  return (
    <div onClick={onChange} style={{ width:34, height:18, borderRadius:9, background:enabled?"var(--green)":"var(--surface-3)", border:`1px solid ${enabled?"var(--green-b)":"var(--border)"}`, cursor:"pointer", position:"relative", flexShrink:0, transition:"background 0.2s" }}>
      <div style={{ position:"absolute", top:2, left:enabled?16:2, width:12, height:12, borderRadius:"50%", background:"#fff", transition:"left 0.2s", boxShadow:"0 1px 3px rgba(0,0,0,0.3)" }}/>
    </div>
  );
}

function AutoPoliciesPanel({ policies, matches, onToggle, onEdit, onDelete, onTrigger }) {
  const [togglingId, setTogglingId] = useState(null);
  const [triggeringId, setTriggeringId] = useState(null);

  const handleToggle = async (id) => { setTogglingId(id); await onToggle(id); setTogglingId(null); };
  const handleTrigger = async (id) => { setTriggeringId(id); await onTrigger(id); setTriggeringId(null); };
  const matchCount = (pid) => (matches||[]).filter(m => m.policy.id === pid).length;

  return (
    <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
      <div>
        <h2 style={{ fontSize:16, fontWeight:600, marginBottom:4 }}>Auto-Remediation Policies</h2>
        <p style={{ fontSize:12, color:"var(--text-2)" }}>{policies.length} policies · {policies.filter(p=>p.enabled).length} enabled</p>
      </div>
      <div style={{ padding:"10px 14px", background:"var(--yellow-dim)", border:"1px solid var(--yellow-b)", borderRadius:"var(--radius-sm)", fontSize:12, color:"var(--yellow)" }}>
        ⚠ <strong>Dry-Run mode</strong> only previews. Toggle <strong>Dry Run OFF</strong> to execute for real.
      </div>
      {policies.length === 0 ? <Empty message="No policies yet." /> : (
        <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
          {policies.map(policy => {
            const count = matchCount(policy.id);
            const isRunning = triggeringId === policy.id;
            return (
              <div key={policy.id} style={{ border:`1px solid ${policy.enabled?(policy.dry_run?"var(--border-strong)":"var(--orange-b)"):"var(--border)"}`, borderRadius:"var(--radius)", background:"var(--surface)", overflow:"hidden" }}>
                <div style={{ padding:"14px 16px" }}>
                  <div style={{ display:"flex", alignItems:"flex-start", gap:12 }}>
                    <div style={{ display:"flex", flexDirection:"column", alignItems:"center", gap:4, flexShrink:0, marginTop:2 }}>
                      {togglingId === policy.id
                        ? <div style={{ width:20, height:20, border:"2px solid var(--border)", borderTop:"2px solid var(--accent)", borderRadius:"50%", animation:"spin 0.7s linear infinite" }}/>
                        : <Toggle enabled={policy.enabled} onChange={() => handleToggle(policy.id)} />}
                      <span style={{ fontSize:9, color:policy.enabled?"var(--green)":"var(--text-3)", fontWeight:600 }}>{policy.enabled?"ON":"OFF"}</span>
                    </div>
                    <div style={{ flex:1, minWidth:0 }}>
                      <div style={{ display:"flex", gap:8, alignItems:"center", flexWrap:"wrap", marginBottom:6 }}>
                        <span style={{ fontSize:13, fontWeight:600 }}>{policy.name}</span>
                        {policy.built_in && <Badge type="neutral">Built-in</Badge>}
                        {policy.enabled && <Badge type={policy.dry_run?"accent":"orange"}>{policy.dry_run?"◎ Dry Run":"● Live"}</Badge>}
                        <Badge type={{CRITICAL:"red",HIGH:"orange",MEDIUM:"yellow",LOW:"neutral"}[policy.severity_threshold]||"neutral"}>≥ {policy.severity_threshold}</Badge>
                        {count > 0 && <Badge type="green">{count} match{count!==1?"es":""}</Badge>}
                      </div>
                      <p style={{ fontSize:12, color:"var(--text-2)", marginBottom:8 }}>{policy.description}</p>
                      <div style={{ display:"flex", gap:16, flexWrap:"wrap", fontSize:11, color:"var(--text-3)" }}>
                        <span>Trigger: <span style={{ fontFamily:"var(--font-mono)", color:"var(--text-2)" }}>{policy.trigger}</span></span>
                        <span>Action: <span style={{ fontFamily:"var(--font-mono)", color:"var(--text-2)" }}>{policy.action}</span></span>
                        <span>Max/run: <strong style={{ color:"var(--text-2)" }}>{policy.max_per_run}</strong></span>
                        <span>Ran: <strong style={{ color:"var(--text-2)" }}>{policy.run_count}×</strong></span>
                      </div>
                    </div>
                    <div style={{ display:"flex", gap:6, flexShrink:0, flexDirection:"column", alignItems:"flex-end" }}>
                      <button onClick={() => handleTrigger(policy.id)} disabled={isRunning||!policy.enabled}
                        style={{ display:"flex", alignItems:"center", gap:6, padding:"5px 12px", fontSize:11, fontFamily:"var(--font-sans)", fontWeight:500, background:policy.enabled?"var(--accent-dim)":"var(--surface-2)", border:`1px solid ${policy.enabled?"var(--accent)":"var(--border)"}`, borderRadius:"var(--radius-sm)", color:policy.enabled?"var(--accent)":"var(--text-3)", cursor:policy.enabled&&!isRunning?"pointer":"not-allowed" }}>
                        {isRunning ? <div style={{ width:12, height:12, border:"2px solid var(--border)", borderTop:"2px solid var(--accent)", borderRadius:"50%", animation:"spin 0.7s linear infinite" }}/> : "▶"}
                        {isRunning?"Running…":"Run Now"}
                      </button>
                      <button onClick={() => onEdit(policy)} style={{ padding:"5px 12px", fontSize:11, fontFamily:"var(--font-sans)", background:"var(--surface-2)", border:"1px solid var(--border)", borderRadius:"var(--radius-sm)", color:"var(--text-2)", cursor:"pointer" }}>Edit</button>
                      {!policy.built_in && <button onClick={() => onDelete(policy.id)} style={{ padding:"5px 12px", fontSize:11, fontFamily:"var(--font-sans)", background:"var(--red-dim)", border:"1px solid var(--red-b)", borderRadius:"var(--radius-sm)", color:"var(--red)", cursor:"pointer" }}>Delete</button>}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

const AUTO_TRIGGERS = [
  { id:"s3_public_access",       label:"S3 — Public access not blocked",  action:"s3_block_public_access",      category:"S3" },
  { id:"s3_no_versioning",       label:"S3 — Versioning disabled",         action:"s3_enable_versioning",        category:"S3" },
  { id:"s3_no_encryption",       label:"S3 — No default encryption",       action:"s3_enable_encryption",        category:"S3" },
  { id:"sg_open_ssh",            label:"Network — Open SSH (0.0.0.0/0)",   action:"sg_remove_open_ssh",          category:"Network" },
  { id:"sg_open_rdp",            label:"Network — Open RDP (0.0.0.0/0)",   action:"sg_remove_open_rdp",          category:"Network" },
  { id:"iam_no_password_policy", label:"IAM — No password policy",         action:"iam_enforce_password_policy", category:"IAM" },
];

function PolicyEditorModal({ policy, onSave, onClose }) {
  const isEdit = !!policy;
  const [saving, setSaving] = useState(false);
  const getTriggerAction   = (tid) => AUTO_TRIGGERS.find(t=>t.id===tid)?.action||"";
  const getTriggerCategory = (tid) => AUTO_TRIGGERS.find(t=>t.id===tid)?.category||"Custom";
  const [form, setForm] = useState({
    name: policy?.name||"", description: policy?.description||"",
    trigger: policy?.trigger||AUTO_TRIGGERS[0].id, action: policy?.action||AUTO_TRIGGERS[0].action,
    category: policy?.category||AUTO_TRIGGERS[0].category, severity_threshold: policy?.severity_threshold||"HIGH",
    enabled: policy?.enabled??false, dry_run: policy?.dry_run??true,
    max_per_run: policy?.max_per_run||5, exclude_resources: (policy?.exclude_resources||[]).join("\n"),
  });
  const set = (k,v) => setForm(f=>({...f,[k]:v}));
  const handleTriggerChange = (tid) => { set("trigger",tid); set("action",getTriggerAction(tid)); set("category",getTriggerCategory(tid)); };
  const handleSubmit = async () => {
    if (!form.name.trim()) return;
    setSaving(true);
    await onSave({ ...(policy||{}), ...form, exclude_resources: form.exclude_resources.split("\n").map(s=>s.trim()).filter(Boolean) });
    setSaving(false);
  };
  const inp = { width:"100%", background:"var(--surface-2)", border:"1px solid var(--border)", borderRadius:"var(--radius-sm)", padding:"8px 12px", fontSize:12, color:"var(--text-1)", fontFamily:"var(--font-sans)", outline:"none" };
  const lbl = { fontSize:11, color:"var(--text-3)", marginBottom:5, display:"block", textTransform:"uppercase", letterSpacing:"0.07em" };
  return (
    <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.75)", zIndex:500, display:"flex", alignItems:"center", justifyContent:"center", padding:24 }}>
      <div style={{ background:"var(--surface)", border:"1px solid var(--border)", borderRadius:"var(--radius)", width:"100%", maxWidth:520, maxHeight:"90vh", overflowY:"auto" }}>
        <div style={{ padding:"16px 20px", borderBottom:"1px solid var(--border)", display:"flex", justifyContent:"space-between", alignItems:"center", position:"sticky", top:0, background:"var(--surface)", zIndex:1 }}>
          <div><div style={{ fontWeight:600, fontSize:14 }}>{isEdit?"Edit Policy":"Create Policy"}</div><div style={{ fontSize:11, color:"var(--text-3)", marginTop:2 }}>Auto-remediation rule</div></div>
          <button onClick={onClose} style={{ background:"none", border:"none", color:"var(--text-2)", fontSize:18, cursor:"pointer" }}>✕</button>
        </div>
        <div style={{ padding:20 }}>
          <div style={{ marginBottom:16 }}><label style={lbl}>Policy name *</label><input style={inp} value={form.name} onChange={e=>set("name",e.target.value)} placeholder="e.g. Block public S3 buckets"/></div>
          <div style={{ marginBottom:16 }}><label style={lbl}>Description</label><textarea style={{ ...inp, resize:"vertical", minHeight:56 }} value={form.description} onChange={e=>set("description",e.target.value)}/></div>
          <div style={{ marginBottom:16 }}>
            <label style={lbl}>Trigger condition</label>
            <select style={{ ...inp, cursor:"pointer" }} value={form.trigger} onChange={e=>handleTriggerChange(e.target.value)}>
              {AUTO_TRIGGERS.map(t=><option key={t.id} value={t.id}>{t.label}</option>)}
            </select>
            <div style={{ fontSize:11, color:"var(--text-3)", marginTop:5 }}>Action: <span style={{ fontFamily:"var(--font-mono)", color:"var(--accent)" }}>{form.action}</span></div>
          </div>
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12, marginBottom:16 }}>
            <div><label style={lbl}>Min severity</label>
              <select style={{ ...inp, cursor:"pointer" }} value={form.severity_threshold} onChange={e=>set("severity_threshold",e.target.value)}>
                {["CRITICAL","HIGH","MEDIUM","LOW"].map(s=><option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div><label style={lbl}>Max per run</label><input style={inp} type="number" min={1} max={100} value={form.max_per_run} onChange={e=>set("max_per_run",parseInt(e.target.value)||5)}/></div>
          </div>
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12, marginBottom:16 }}>
            <div style={{ display:"flex", alignItems:"center", gap:10, padding:"10px 14px", background:"var(--surface-2)", border:"1px solid var(--border)", borderRadius:"var(--radius-sm)" }}>
              <Toggle enabled={form.enabled} onChange={()=>set("enabled",!form.enabled)}/>
              <div><div style={{ fontSize:12, fontWeight:500 }}>Enabled</div><div style={{ fontSize:11, color:"var(--text-3)" }}>Policy is active</div></div>
            </div>
            <div style={{ display:"flex", alignItems:"center", gap:10, padding:"10px 14px", background:form.dry_run?"var(--accent-dim)":"var(--orange-dim)", border:`1px solid ${form.dry_run?"var(--accent)":"var(--orange-b)"}`, borderRadius:"var(--radius-sm)" }}>
              <Toggle enabled={form.dry_run} onChange={()=>set("dry_run",!form.dry_run)}/>
              <div><div style={{ fontSize:12, fontWeight:500, color:form.dry_run?"var(--accent)":"var(--orange)" }}>{form.dry_run?"Dry Run":"⚠ LIVE"}</div><div style={{ fontSize:11, color:"var(--text-3)" }}>{form.dry_run?"Preview only":"Executes for real"}</div></div>
            </div>
          </div>
          <div style={{ marginBottom:20 }}><label style={lbl}>Exclude resources (one per line)</label><textarea style={{ ...inp, resize:"vertical", minHeight:64, fontFamily:"var(--font-mono)", fontSize:11 }} value={form.exclude_resources} onChange={e=>set("exclude_resources",e.target.value)} placeholder="bucket-name-to-skip"/></div>
          <div style={{ display:"flex", gap:10, justifyContent:"flex-end" }}>
            <button onClick={onClose} style={{ padding:"8px 20px", background:"var(--surface-2)", border:"1px solid var(--border)", borderRadius:"var(--radius-sm)", fontSize:13, color:"var(--text-2)", cursor:"pointer", fontFamily:"var(--font-sans)" }}>Cancel</button>
            <button onClick={handleSubmit} disabled={!form.name.trim()||saving} style={{ padding:"8px 20px", background:form.name.trim()?"var(--accent)":"var(--surface-3)", border:"none", borderRadius:"var(--radius-sm)", fontSize:13, color:form.name.trim()?"#fff":"var(--text-3)", cursor:form.name.trim()?"pointer":"not-allowed", fontFamily:"var(--font-sans)", fontWeight:600 }}>
              {saving?"Saving…":isEdit?"Save Changes":"Create Policy"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function AutoIssuesPanel({ issues, matches }) {
  const [filter,setFilter]=useState(""), [sevFilter,setSevFilter]=useState("");
  const matchMap={};
  (matches||[]).forEach(m=>{ const k=`${m.issue.resource_id}_${m.issue.trigger}`; if(!matchMap[k])matchMap[k]=[]; matchMap[k].push(m); });
  const filtered=(issues||[]).filter(i=>{ const q=filter.toLowerCase(); return(!q||i.resource_id?.toLowerCase().includes(q)||i.detail?.toLowerCase().includes(q))&&(!sevFilter||i.severity===sevFilter); });
  const SS={ background:"var(--surface)", border:"1px solid var(--border)", borderRadius:"var(--radius-sm)", padding:"7px 10px", fontSize:12, color:"var(--text-1)", fontFamily:"var(--font-sans)", outline:"none", cursor:"pointer" };
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:16 }}>
      <div><h2 style={{ fontSize:16, fontWeight:600, marginBottom:4 }}>Issues Found</h2><p style={{ fontSize:12, color:"var(--text-2)" }}>{(issues||[]).length} issues · {(matches||[]).length} matched to policy</p></div>
      <div style={{ display:"flex", gap:8 }}>
        <input value={filter} onChange={e=>setFilter(e.target.value)} placeholder="Search resource or description…" style={{ flex:1, ...SS, padding:"7px 12px" }}/>
        <select value={sevFilter} onChange={e=>setSevFilter(e.target.value)} style={SS}>
          <option value="">All Severities</option>
          {["CRITICAL","HIGH","MEDIUM","LOW"].map(s=><option key={s} value={s}>{s}</option>)}
        </select>
        {(filter||sevFilter)&&<button onClick={()=>{setFilter("");setSevFilter("");}} style={{ ...SS, color:"var(--text-2)" }}>Clear</button>}
      </div>
      {filtered.length===0 ? <Empty message="No issues found — your environment looks clean!"/> : (
        <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
          {filtered.map((issue,i)=>{ const key=`${issue.resource_id}_${issue.trigger}`; const pm=matchMap[key]||[]; const isM=pm.length>0; return (
            <div key={i} style={{ border:`1px solid ${isM?"var(--green-b)":issue.severity==="CRITICAL"?"var(--red-b)":"var(--border)"}`, borderRadius:"var(--radius)", background:"var(--surface)", padding:"12px 16px" }}>
              <div style={{ display:"flex", alignItems:"flex-start", gap:10 }}>
                <div style={{ flexShrink:0, marginTop:1 }}>{severityBadge(issue.severity)}</div>
                <div style={{ flex:1, minWidth:0 }}>
                  <div style={{ fontSize:12, fontWeight:500, marginBottom:4 }}>{issue.detail}</div>
                  <div style={{ display:"flex", gap:8, flexWrap:"wrap", alignItems:"center", fontSize:11, color:"var(--text-2)" }}>
                    <Mono>{issue.resource_id}</Mono>
                    <span style={{ color:"var(--text-3)" }}>{issue.resource_type?.replace("AWS::","")}</span>
                    <Badge type="neutral">{issue.trigger}</Badge>
                  </div>
                  {isM&&<div style={{ marginTop:8, display:"flex", gap:6, flexWrap:"wrap" }}>{pm.map((m,mi)=><div key={mi} style={{ fontSize:11, padding:"3px 10px", borderRadius:10, background:m.would_execute?"var(--orange-dim)":"var(--accent-dim)", border:`1px solid ${m.would_execute?"var(--orange-b)":"var(--border-strong)"}`, color:m.would_execute?"var(--orange)":"var(--accent)" }}>{m.would_execute?"● Will fix:":"◎ Dry-run:"} {m.policy.name}</div>)}</div>}
                </div>
                {isM ? <Badge type="green">✓ Policy Matched</Badge> : <Badge type="neutral">No Policy</Badge>}
              </div>
            </div>
          ); })}
        </div>
      )}
    </div>
  );
}

function AutoExecutionHistory({ executions }) {
  const [expanded,setExpanded]=useState(null), [filter,setFilter]=useState("all");
  const filtered = filter==="all" ? executions : executions.filter(e=>e.status===filter.toUpperCase()||(filter==="dry_run"&&e.status==="DRY_RUN"));
  if (!executions.length) return (<div style={{ display:"flex", flexDirection:"column", gap:16 }}><h2 style={{ fontSize:16, fontWeight:600 }}>Execution History</h2><Empty message="No executions yet. Enable a policy and run it."/></div>);
  return (
    <div style={{ display:"flex", flexDirection:"column", gap:20 }}>
      <div><h2 style={{ fontSize:16, fontWeight:600, marginBottom:4 }}>Execution History</h2><p style={{ fontSize:12, color:"var(--text-2)" }}>Full log of every auto-remediation execution</p></div>
      <StatGrid stats={[
        {label:"Total",value:executions.length,accent:true},
        {label:"Successful",value:executions.filter(e=>e.status==="SUCCESS").length,color:"var(--green)"},
        {label:"Dry-Run",value:executions.filter(e=>e.status==="DRY_RUN").length,color:"var(--accent)"},
        {label:"Failed",value:executions.filter(e=>e.status==="FAILED").length,color:"var(--red)"},
      ]}/>
      <div style={{ display:"flex", gap:1, background:"var(--border)", borderRadius:"var(--radius-sm)", overflow:"hidden", width:"fit-content" }}>
        {[["all","All"],["success","Success"],["dry_run","Dry-Run"],["failed","Failed"]].map(([v,l])=>(
          <button key={v} onClick={()=>setFilter(v)} style={{ padding:"5px 14px", fontSize:11, border:"none", cursor:"pointer", background:filter===v?"var(--surface)":"transparent", color:filter===v?"var(--text-1)":"var(--text-3)", fontFamily:"var(--font-sans)", fontWeight:filter===v?500:400 }}>{l}</button>
        ))}
      </div>
      <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
        {filtered.map(entry=>{ const isExp=expanded===entry.id; const hB=entry.before_state&&Object.keys(entry.before_state).length>0; const hA=entry.after_state&&Object.keys(entry.after_state).length>0; return (
          <div key={entry.id} style={{ border:"1px solid var(--border)", borderRadius:"var(--radius)", background:"var(--surface)", overflow:"hidden" }}>
            <div style={{ padding:"12px 16px", display:"flex", alignItems:"flex-start", gap:12, cursor:(hB||hA)?"pointer":"default" }} onClick={()=>(hB||hA)?setExpanded(isExp?null:entry.id):null}>
              <div style={{ flexShrink:0, textAlign:"right", minWidth:44 }}><div style={{ fontFamily:"var(--font-mono)", fontSize:11, color:"var(--text-3)" }}>#{entry.id}</div><div style={{ fontSize:10, color:"var(--text-3)", marginTop:2 }}>{entry.timestamp?.slice(11)}</div></div>
              <div style={{ flexShrink:0 }}>{statusBadge(entry.status)}</div>
              <div style={{ flex:1, minWidth:0 }}>
                <div style={{ fontSize:12, fontWeight:500, marginBottom:3 }}>{entry.detail}</div>
                <div style={{ display:"flex", gap:8, flexWrap:"wrap", fontSize:11, color:"var(--text-2)" }}>
                  <Mono>{entry.resource_id?.slice(0,30)}</Mono>
                  <span style={{ color:"var(--accent)", fontStyle:"italic" }}>{entry.policy_name}</span>
                  {entry.dry_run&&<Badge type="accent">DRY RUN</Badge>}
                </div>
              </div>
              {(hB||hA)&&<span style={{ fontSize:12, color:"var(--text-3)", flexShrink:0, marginTop:2 }}>{isExp?"▲":"▼"}</span>}
            </div>
            {isExp&&(hB||hA)&&(
              <div style={{ borderTop:"1px solid var(--border)", padding:"12px 16px", display:"grid", gridTemplateColumns:"1fr 1fr", gap:12 }}>
                {hB&&<div><div style={{ fontSize:10, color:"var(--text-3)", marginBottom:6, textTransform:"uppercase" }}>Before</div><pre style={{ fontSize:11, fontFamily:"var(--font-mono)", color:"var(--red)", background:"var(--red-dim)", padding:"8px 12px", borderRadius:4, overflow:"auto", maxHeight:100 }}>{JSON.stringify(entry.before_state,null,2)}</pre></div>}
                {hA&&<div><div style={{ fontSize:10, color:"var(--text-3)", marginBottom:6, textTransform:"uppercase" }}>After</div><pre style={{ fontSize:11, fontFamily:"var(--font-mono)", color:"var(--green)", background:"var(--green-dim)", padding:"8px 12px", borderRadius:4, overflow:"auto", maxHeight:100 }}>{JSON.stringify(entry.after_state,null,2)}</pre></div>}
              </div>
            )}
          </div>
        ); })}
      </div>
    </div>
  );
}

function AutoRemediationDashboard({ data, meta, executions, onTrigger, onToggle, onSave, onDelete, onRescan }) {
  const [active,setActive]=useState("overview");
  const [showEditor,setShowEditor]=useState(false);
  const [editPolicy,setEditPolicy]=useState(null);
  const [triggering,setTriggering]=useState(false);
  const summary=data.summary||{}, policies=data.policies||[], issues=data.issues||[], matches=data.matches||[];
  const enabledCount=policies.filter(p=>p.enabled).length;
  const successExecs=executions.filter(e=>e.status==="SUCCESS").length;
  const dryRunExecs=executions.filter(e=>e.status==="DRY_RUN").length;

  const handleTriggerAll = async () => { setTriggering(true); await onTrigger(null); setTriggering(false); setActive("history"); };
  const handleTriggerOne = async (pid) => { setTriggering(true); await onTrigger(pid); setTriggering(false); };
  const handleEdit = (p) => { setEditPolicy(p); setShowEditor(true); };
  const handleSavePolicy = async (p) => { await onSave(p); setShowEditor(false); setEditPolicy(null); };

  const NAV = [
    {id:"overview",label:"Overview",icon:"◈"},
    {id:"policies",label:"Policies",icon:"⚙",badge:enabledCount>0?enabledCount:null,badgeColor:"var(--accent)"},
    {id:"issues",label:"Issues Found",icon:"⚠",badge:issues.length>0?issues.length:null,badgeColor:"var(--yellow)"},
    {id:"history",label:"Exec History",icon:"◎",badge:executions.length>0?executions.length:null,badgeColor:"var(--green)"},
  ];

  return (
    <div style={{ display:"flex", minHeight:"calc(100vh - 108px)" }}>
      {showEditor&&<PolicyEditorModal policy={editPolicy} onSave={handleSavePolicy} onClose={()=>{setShowEditor(false);setEditPolicy(null);}}/>}
      <aside style={{ width:210, borderRight:"1px solid var(--border)", background:"var(--surface)", padding:"16px 0", position:"sticky", top:108, height:"calc(100vh - 108px)", overflowY:"auto", flexShrink:0 }}>
        <div style={{ padding:"0 16px 14px", borderBottom:"1px solid var(--border)", marginBottom:8 }}>
          <div style={{ fontSize:10, color:"var(--text-3)", marginBottom:4, textTransform:"uppercase", letterSpacing:"0.06em" }}>Account</div>
          <div style={{ fontFamily:"var(--font-mono)", fontSize:12, fontWeight:500 }}>{data.identity?.account_id}</div>
          <div style={{ fontSize:10, color:"var(--text-3)", marginTop:4 }}>{data.region} · {meta?.duration}s</div>
        </div>
        <div style={{ padding:"8px 16px 14px", borderBottom:"1px solid var(--border)", marginBottom:8 }}>
          <StatGrid stats={[
            {label:"Total Issues",value:summary.total_issues??0,color:"var(--yellow)"},
            {label:"Auto-Fixable",value:summary.auto_fixable??0,color:"var(--green)"},
            {label:"Live Fixed",value:successExecs,color:"var(--green)"},
          ]}/>
        </div>
        {NAV.map(item=>{const isA=active===item.id; return(
          <button key={item.id} onClick={()=>setActive(item.id)} style={{ display:"flex", alignItems:"center", justifyContent:"space-between", width:"100%", padding:"7px 16px", border:"none", borderLeft:isA?"2px solid var(--purple)":"2px solid transparent", background:isA?"var(--purple-dim)":"none", color:isA?"var(--purple)":"var(--text-2)", fontFamily:"var(--font-sans)", fontSize:13, cursor:"pointer", fontWeight:isA?500:400 }}>
            <span style={{ display:"flex", alignItems:"center", gap:8 }}><span style={{ fontSize:12, opacity:0.7 }}>{item.icon}</span>{item.label}</span>
            {item.badge&&<span style={{ fontFamily:"var(--font-mono)", fontSize:11, fontWeight:600, color:item.badgeColor||"var(--accent)" }}>{item.badge}</span>}
          </button>
        );})}
        <div style={{ padding:"16px" }}>
          <button onClick={handleTriggerAll} disabled={triggering||enabledCount===0}
            style={{ width:"100%", padding:"8px 0", background:enabledCount>0?"var(--purple-dim)":"var(--surface-2)", border:`1px solid ${enabledCount>0?"var(--purple)":"var(--border)"}`, borderRadius:"var(--radius-sm)", fontSize:12, color:enabledCount>0?"var(--purple)":"var(--text-3)", cursor:enabledCount>0?"pointer":"not-allowed", fontFamily:"var(--font-sans)", fontWeight:500 }}>
            {triggering?"Running…":"▶ Run All Policies"}
          </button>
          <button onClick={()=>setShowEditor(true)} style={{ width:"100%", marginTop:8, padding:"7px 0", background:"var(--surface-2)", border:"1px solid var(--border)", borderRadius:"var(--radius-sm)", fontSize:12, color:"var(--text-2)", cursor:"pointer", fontFamily:"var(--font-sans)" }}>+ New Policy</button>
          <button onClick={onRescan} style={{ width:"100%", marginTop:6, padding:"6px 0", background:"none", border:"1px solid var(--border)", borderRadius:"var(--radius-sm)", fontSize:12, color:"var(--text-3)", cursor:"pointer", fontFamily:"var(--font-sans)" }}>↻ Re-scan</button>
        </div>
      </aside>
      <main style={{ flex:1, minWidth:0, padding:"24px 28px", animation:"fadeIn 0.3s ease", overflowX:"hidden" }} key={active}>
        {active==="overview"&&(
          <div style={{ display:"flex", flexDirection:"column", gap:24 }}>
            <div><h2 style={{ fontSize:16, fontWeight:700, marginBottom:4 }}>Auto Remediation Overview</h2><p style={{ fontSize:12, color:"var(--text-2)" }}>{meta?.timestamp} · {data.region} · {meta?.duration}s</p></div>
            <StatGrid stats={[
              {label:"Total Issues",value:summary.total_issues??0,color:"var(--yellow)"},
              {label:"Auto-Fixable",value:summary.auto_fixable??0,color:"var(--green)"},
              {label:"Enabled Policies",value:summary.enabled_policies??0,color:"var(--accent)"},
              {label:"Live Mode",value:summary.live_policies??0,color:(summary.live_policies??0)>0?"var(--orange)":"var(--text-3)"},
              {label:"Dry-Run Mode",value:summary.dry_run_policies??0,color:"var(--accent)"},
              {label:"Auto-Fixed",value:successExecs,color:"var(--green)"},
              {label:"Previewed",value:dryRunExecs,color:"var(--accent)"},
            ]}/>
            {matches.length>0&&(
              <div>
                <SectionTitle>Matched Issues (Ready to Execute)</SectionTitle>
                <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
                  {matches.slice(0,8).map((m,i)=>(
                    <div key={i} style={{ padding:"10px 14px", background:"var(--surface)", border:`1px solid ${m.would_execute?"var(--orange-b)":"var(--border)"}`, borderRadius:"var(--radius)" }}>
                      <div style={{ display:"flex", gap:8, alignItems:"center", flexWrap:"wrap" }}>
                        {severityBadge(m.issue.severity)}
                        <span style={{ fontSize:12, fontWeight:500, flex:1 }}>{m.issue.detail}</span>
                        <Badge type={m.would_execute?"orange":"accent"}>{m.would_execute?"● Live":"◎ Dry-run"}</Badge>
                        <span style={{ fontSize:11, color:"var(--text-2)" }}>{m.policy.name}</span>
                      </div>
                    </div>
                  ))}
                  {matches.length>8&&<div style={{ fontSize:12, color:"var(--text-3)", textAlign:"center" }}>+{matches.length-8} more matches</div>}
                </div>
              </div>
            )}
          </div>
        )}
        {active==="policies"&&<AutoPoliciesPanel policies={policies} matches={matches} onToggle={onToggle} onEdit={handleEdit} onDelete={onDelete} onTrigger={handleTriggerOne}/>}
        {active==="issues"&&<AutoIssuesPanel issues={issues} matches={matches}/>}
        {active==="history"&&<AutoExecutionHistory executions={executions}/>}
      </main>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// ROOT APP — All 5 Phases Unified + Dark/Light Mode
// ═══════════════════════════════════════════════════════════════════════════════
const MODULES = [
  { id:"discovery",    label:"Asset Inventory",    phase:"Phase 1", icon:"⬡", color:"var(--accent)",  desc:"300+ resource types via Config" },
  { id:"compliance",  label:"Compliance Checker",  phase:"Phase 2", icon:"⬢", color:"var(--red)",    desc:"Rules, IAM, CloudTrail & more"  },
  { id:"risk",        label:"Risk Dashboard",      phase:"Phase 3", icon:"★", color:"var(--orange)", desc:"CVEs, threats & anomalies"      },
  { id:"remediation", label:"Manual Remediation",  phase:"Phase 4", icon:"✓", color:"var(--green)",  desc:"One-click fixes with audit log"  },
  { id:"auto",        label:"Auto Remediation",    phase:"Phase 5", icon:"⚡", color:"var(--purple)", desc:"Policy-based auto-fixing"       },
];

export default function App() {
  const [activeModule, setActiveModule] = useState("discovery");
  const [savedCreds, setSavedCreds]     = useState(null);
  const [darkMode, setDarkMode]         = useState(true);
  const [moduleState, setModuleState]   = useState({
    discovery:   { data:null, loading:false, error:null, meta:null },
    compliance:  { data:null, loading:false, error:null, meta:null },
    risk:        { data:null, loading:false, error:null, meta:null },
    remediation: { data:null, loading:false, error:null, meta:null, auditLog:[], creds:null },
    auto:        { data:null, loading:false, error:null, meta:null, executions:[], creds:null },
  });

  const ENDPOINTS = {
    discovery:   "/api/scan",
    compliance:  "/api/compliance/scan",
    risk:        "/api/risk/scan",
    remediation: "/api/remediation/scan",
    auto:        "/api/auto/scan",
  };

  const patch = (mod, p) => setModuleState(prev=>({...prev,[mod]:{...prev[mod],...p}}));

  const handleScan = async (creds) => {
    setSavedCreds(creds);
    patch(activeModule, { loading:true, error:null, data:null, creds });
    const t0 = Date.now();
    try {
      const res  = await fetch(ENDPOINTS[activeModule], { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(creds) });
      const json = await res.json();
      const meta = { duration:((Date.now()-t0)/1000).toFixed(1), timestamp:new Date().toLocaleString(), region:creds.region||"All Regions" };
      if(json.error) patch(activeModule, { error:json.error, loading:false });
      else patch(activeModule, { data:json, loading:false, meta });
    } catch(e) {
      patch(activeModule, { error:"Cannot reach backend on port 5015. Ensure Flask server is running.", loading:false });
    }
  };

  const handleRemediate = async (actionId, resource, params={}) => {
    const remState = moduleState.remediation;
    if (!remState.creds) return { success:false, detail:"No credentials." };
    try {
      const res  = await fetch("/api/remediation/execute", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ ...remState.creds, actionId, resource, params }) });
      const json = await res.json();
      fetchAuditLog();
      return json;
    } catch(e) { return { success:false, detail:String(e) }; }
  };

  const fetchAuditLog = async () => {
    try { const res=await fetch("/api/remediation/audit"); const json=await res.json(); patch("remediation",{auditLog:json.log||[]}); } catch {}
  };

  const fetchAutoExecs = async () => {
    try { const res=await fetch("/api/auto/executions"); const json=await res.json(); patch("auto",{executions:json.executions||[]}); } catch {}
  };

  const handleAutoTrigger = async (policy_id=null) => {
    const autoState = moduleState.auto;
    if (!autoState.creds) return [];
    try {
      const res  = await fetch("/api/auto/trigger", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({...autoState.creds, policy_id}) });
      const json = await res.json();
      await fetchAutoExecs();
      await handleAutoRescan();
      return json.results||[];
    } catch { return []; }
  };

  const handleAutoRescan = async () => {
    const autoState = moduleState.auto;
    if (!autoState.creds) return;
    try { const res=await fetch("/api/auto/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(autoState.creds)}); const json=await res.json(); if(!json.error)patch("auto",{data:json}); } catch {}
  };

  const handlePolicyToggle = async (pid) => { await fetch(`/api/auto/policies/${pid}/toggle`,{method:"POST"}); handleAutoRescan(); };
  const handlePolicySave   = async (p) => { await fetch("/api/auto/policies",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(p)}); handleAutoRescan(); };
  const handlePolicyDelete = async (pid) => { await fetch(`/api/auto/policies/${pid}/delete`,{method:"POST"}); handleAutoRescan(); };

  useMemo(()=>{
    if(moduleState.auto.data){ fetchAutoExecs(); }
  },[moduleState.auto.data]);

  const mod = moduleState[activeModule];

  const badges = {
    discovery:   moduleState.discovery.data  ? Object.values(moduleState.discovery.data.summary||{}).reduce((a,b)=>a+b,0).toLocaleString()+" res" : null,
    compliance:  moduleState.compliance.data ? `${moduleState.compliance.data.score?.overall??0}% (${moduleState.compliance.data.score?.grade||"—"})` : null,
    risk:        moduleState.risk.data       ? moduleState.risk.data.risk_score?.level : null,
    remediation: moduleState.remediation.data ? `${moduleState.remediation.data.summary?.total_issues??0} issues` : null,
    auto:        moduleState.auto.data       ? `${moduleState.auto.data.summary?.total_issues??0} issues` : null,
  };

  const remState  = moduleState.remediation;
  const autoState = moduleState.auto;

  // Theme class
  const themeClass = darkMode ? "" : "light";

  const scanningLabel = {
    discovery:   { title:"Discovering AWS Resources",     color:"var(--accent)",  step:"Querying AWS Config across all regions…" },
    compliance:  { title:"Running Compliance Checks",     color:"var(--red)",     step:"Checking Config Rules, Security Hub, IAM…" },
    risk:        { title:"Scanning for Risks",            color:"var(--orange)",  step:"Inspector CVEs, Macie, GuardDuty, Health…" },
    remediation: { title:"Scanning for Remediable Issues",color:"var(--green)",   step:"Checking S3 buckets, security groups, IAM…" },
    auto:        { title:"Scanning & Evaluating Policies",color:"var(--purple)",  step:"Loading policies, matching issues…" },
  }[activeModule];

  return (
    <div className={themeClass} style={{ display:"flex", flexDirection:"column", minHeight:"100vh" }}>

      {/* ── Top Header ── */}
      <header style={{ height:56, display:"flex", alignItems:"center", justifyContent:"space-between", padding:"0 20px", borderBottom:"1px solid var(--border)", background:"var(--surface)", position:"sticky", top:0, zIndex:300 }}>
        <div style={{ display:"flex", alignItems:"center", gap:12 }}>
          <div style={{ width:32, height:32, borderRadius:8, background:"linear-gradient(135deg,#1a3a6a,#0d1f3c)", border:"1px solid var(--border-strong)", display:"flex", alignItems:"center", justifyContent:"center" }}>
            <svg width="18" height="18" viewBox="0 0 18 18" fill="none"><rect x="2" y="2" width="14" height="14" rx="3" stroke="#3b82f6" strokeWidth="1.5"/><path d="M5 9h8M9 5v8" stroke="#3b82f6" strokeWidth="1.5" strokeLinecap="round"/></svg>
          </div>
          <div>
            <div style={{ fontSize:13, fontWeight:700, letterSpacing:"-0.02em" }}>AWS Security Platform</div>
            <div style={{ fontSize:10, color:"var(--text-3)", letterSpacing:"0.05em" }}>UNIFIED CLOUD SECURITY · ALL 5 PHASES</div>
          </div>
        </div>

        {/* Module Switcher */}
        <div style={{ display:"flex", gap:2, background:"var(--surface-2)", border:"1px solid var(--border)", borderRadius:10, padding:3 }}>
          {MODULES.map(m=>{ const isA=activeModule===m.id; return(
            <button key={m.id} onClick={()=>setActiveModule(m.id)} style={{ display:"flex", alignItems:"center", gap:7, padding:"5px 14px", borderRadius:8, border:"none", background:isA?m.color+"22":"transparent", color:isA?m.color:"var(--text-2)", cursor:"pointer", fontFamily:"var(--font-sans)", fontSize:12, fontWeight:isA?600:400, transition:"all 0.15s", boxShadow:isA?`0 0 10px ${m.color}20`:"none" }}>
              <span style={{ fontSize:14 }}>{m.icon}</span>
              <span style={{ display:"flex", flexDirection:"column", alignItems:"flex-start", lineHeight:1.2 }}>
                <span>{m.label}</span>
                {badges[m.id]&&<span style={{ fontSize:9, fontFamily:"var(--font-mono)", opacity:0.8 }}>{badges[m.id]}</span>}
              </span>
            </button>
          );})}
        </div>

        <div style={{ display:"flex", alignItems:"center", gap:10 }}>
          {/* Dark/Light Mode Toggle */}
          <button onClick={()=>setDarkMode(d=>!d)} title={darkMode?"Switch to Light Mode":"Switch to Dark Mode"}
            style={{ display:"flex", alignItems:"center", gap:6, padding:"5px 12px", background:"var(--surface-2)", border:"1px solid var(--border)", borderRadius:"var(--radius-sm)", cursor:"pointer", fontSize:11, color:"var(--text-2)", fontFamily:"var(--font-sans)" }}>
            <span>{darkMode?"☀ Light":"🌙 Dark"}</span>
          </button>
          <span style={{ fontSize:10, padding:"2px 8px", borderRadius:8, background:"var(--surface-3)", color:"var(--text-3)", border:"1px solid var(--border)", fontWeight:500 }}>{MODULES.find(m=>m.id===activeModule)?.phase}</span>
          {mod.data&&(<button onClick={()=>patch(activeModule,{data:null,error:null,meta:null})} style={{ background:"var(--surface-2)", border:"1px solid var(--border)", borderRadius:"var(--radius-sm)", padding:"5px 12px", fontSize:12, color:"var(--text-2)", cursor:"pointer", fontFamily:"var(--font-sans)" }}>← New Scan</button>)}
        </div>
      </header>

      {/* ── Status Bar ── */}
      <div style={{ height:44, display:"flex", alignItems:"center", padding:"0 20px", borderBottom:"1px solid var(--border)", background:"var(--bg)", gap:8, overflowX:"auto" }}>
        {MODULES.map(m=>{ const ms=moduleState[m.id], isA=activeModule===m.id; const dotColor=ms.data?"var(--green)":ms.loading?m.color:ms.error?"var(--red)":"var(--text-3)"; const statusText=ms.data?"Complete":ms.loading?"Scanning…":ms.error?"Error":"Not scanned"; return(
          <div key={m.id} onClick={()=>setActiveModule(m.id)} style={{ display:"flex", alignItems:"center", gap:8, padding:"5px 12px", borderRadius:"var(--radius-sm)", background:isA?"var(--surface)":"transparent", border:isA?"1px solid var(--border)":"1px solid transparent", cursor:"pointer", flexShrink:0 }}>
            <div style={{ width:6, height:6, borderRadius:"50%", background:dotColor, animation:ms.loading?"pulse 1.5s ease infinite":"none", boxShadow:ms.data?`0 0 6px var(--green)`:"none" }}/>
            <span style={{ fontSize:11, color:isA?"var(--text-1)":"var(--text-3)", fontWeight:isA?500:400 }}>{m.label}</span>
            <span style={{ fontSize:10, color:dotColor, fontFamily:"var(--font-mono)" }}>{statusText}</span>
          </div>
        );})}
      </div>

      {/* ── Content ── */}
      <main style={{ flex:1 }}>
        {mod.loading&&(
          <div style={{ display:"flex", alignItems:"center", justifyContent:"center", minHeight:"calc(100vh - 108px)" }}>
            <div style={{ display:"flex", flexDirection:"column", alignItems:"center", gap:24 }}>
              <div style={{ width:44, height:44, border:`2px solid var(--border)`, borderTop:`2px solid ${scanningLabel.color}`, borderRadius:"50%", animation:"spin 0.8s linear infinite", boxShadow:`0 0 16px ${scanningLabel.color}40` }}/>
              <div style={{ textAlign:"center" }}>
                <p style={{ fontWeight:600, fontSize:16, marginBottom:8 }}>{scanningLabel.title}</p>
                <p style={{ color:scanningLabel.color, fontSize:12, fontFamily:"var(--font-mono)", animation:"pulse 1.5s ease infinite" }}>{scanningLabel.step}</p>
                <p style={{ color:"var(--text-3)", fontSize:12, marginTop:8 }}>This may take 1–3 minutes</p>
              </div>
            </div>
          </div>
        )}
        {!mod.loading&&!mod.data&&(
          <div style={{ display:"flex", alignItems:"center", justifyContent:"center", minHeight:"calc(100vh - 108px)", padding:24 }}>
            <CredentialsForm onScan={handleScan} error={mod.error} savedCreds={savedCreds} activeModule={activeModule}/>
          </div>
        )}
        {!mod.loading&&mod.data&&(
          <div style={{ animation:"fadeIn 0.3s ease" }}>
            {activeModule==="discovery"   && <DiscoveryDashboard   data={mod.data} meta={mod.meta}/>}
            {activeModule==="compliance"  && <ComplianceDashboard  data={mod.data} meta={mod.meta}/>}
            {activeModule==="risk"        && <RiskDashboard        data={mod.data} meta={mod.meta}/>}
            {activeModule==="remediation" && <RemediationDashboard data={mod.data} meta={mod.meta} onRemediate={handleRemediate} auditLog={remState.auditLog} onRescan={()=>handleScan(remState.creds)}/>}
            {activeModule==="auto"        && <AutoRemediationDashboard data={mod.data} meta={mod.meta} executions={autoState.executions} onTrigger={handleAutoTrigger} onToggle={handlePolicyToggle} onSave={handlePolicySave} onDelete={handlePolicyDelete} onRescan={handleAutoRescan}/>}
          </div>
        )}
      </main>
    </div>
  );
}
