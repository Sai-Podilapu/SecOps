import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClientModule } from '@angular/common/http';
import { ApiService, AwsCreds, AzureCreds } from './services/api.service';

// AWS Components
import { CredentialsComponent } from './components/credentials/credentials.component';
import { DiscoveryComponent }   from './components/modules/discovery.component';
import { ComplianceComponent }  from './components/modules/compliance.component';
import { RiskComponent }        from './components/modules/risk.component';
import { CspmComponent }        from './components/modules/cspm.component';
import { MaturityComponent }    from './components/modules/maturity.component';
import { WellarchComponent }    from './components/modules/wellarch.component';

// Azure Components
import { AzureCredentialsComponent } from './components/azure/azure-credentials.component';
import { AzureDiscoveryComponent }   from './components/azure/azure-discovery.component';
import { AzureComplianceComponent }  from './components/azure/azure-compliance.component';
import { AzureRiskComponent }        from './components/azure/azure-risk.component';
import { AzureCspmComponent }        from './components/azure/azure-cspm.component';
import { AzureMaturityComponent }    from './components/azure/azure-maturity.component';
import { AzureWellarchComponent }    from './components/azure/azure-wellarch.component';

const MODULES = [
  { id:'overview',   label:'Executive Overview',  phase:'Home',    icon:'◐', color:'var(--accent)',  awsDesc:'Unified security posture across all modules', azureDesc:'Unified security posture across all modules' },
  { id:'discovery',  label:'Asset Inventory',     phase:'Phase 1', icon:'⬡', color:'var(--accent)',  awsDesc:'300+ resource types via Config',           azureDesc:'All resources via Resource Graph' },
  { id:'compliance', label:'Compliance Checker',  phase:'Phase 2', icon:'⬢', color:'var(--red)',     awsDesc:'Config Rules, IAM, CloudTrail & more',     azureDesc:'Defender, Policy, IAM, Activity Log' },
  { id:'risk',       label:'Risk Dashboard',      phase:'Phase 3', icon:'★', color:'var(--orange)',  awsDesc:'CVEs, threats & anomalies',                azureDesc:'Defender alerts, Advisor, Monitor' },
  { id:'cspm',       label:'CSPM Dashboard',      phase:'Phase 4', icon:'◉', color:'#0ea5e9',        awsDesc:'Compute, Container, DB, Network, WAF, CIS', azureDesc:'Compute, Storage, Network, KeyVault, CIS' },
  { id:'maturity',   label:'Maturity Assessment', phase:'Phase 5', icon:'◈', color:'var(--cyan)',    awsDesc:'5-domain SecOps maturity score',            azureDesc:'Identity, Infra, Data, Detection, Response' },
  { id:'wellarch',   label:'Well-Architected',    phase:'Phase 6', icon:'◇', color:'#a855f7',        awsDesc:'6-pillar AWS framework review',             azureDesc:'Azure WAF — 5-pillar review' },
];

interface ModState {
  data: any; loading: boolean; error: string; meta: any; creds: any;
}

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [
    CommonModule, HttpClientModule,
    // AWS
    CredentialsComponent, DiscoveryComponent, ComplianceComponent,
    RiskComponent, CspmComponent, MaturityComponent, WellarchComponent,
    // Azure
    AzureCredentialsComponent, AzureDiscoveryComponent, AzureComplianceComponent,
    AzureRiskComponent, AzureCspmComponent, AzureMaturityComponent, AzureWellarchComponent,
  ],
  templateUrl: './app.component.html',
})
export class AppComponent {
  modules      = MODULES;
  // Default landing page is now the Executive Overview
  activeModule = 'overview';
  cloud: 'aws' | 'azure' = 'aws';
  darkMode     = false;
  showCloudMenu = false;

  // Report export modal state (UI only)
  showReport = false;
  reportFormat: 'pdf' | 'word' | 'excel' | 'text' = 'pdf';
  reportType: 'executive' | 'findings' | 'compliance' | 'risk' | 'full' = 'executive';

  // Separate saved creds per cloud
  savedAwsCreds:   any = null;
  savedAzureCreds: any = null;

  // Separate state per cloud + module
  awsState:   Record<string, ModState> = Object.fromEntries(MODULES.map(m => [m.id, { data:null, loading:false, error:'', meta:null, creds:null }]));
  azureState: Record<string, ModState> = Object.fromEntries(MODULES.map(m => [m.id, { data:null, loading:false, error:'', meta:null, creds:null }]));

  constructor(private api: ApiService) {
    // Persisted theme
    try {
      const t = typeof localStorage !== 'undefined' ? localStorage.getItem('secops.theme') : null;
      if (t === 'dark') this.darkMode = true;
      if (t === 'light') this.darkMode = false;
      if (!t && typeof window !== 'undefined' && window.matchMedia) {
        this.darkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;
      }
    } catch {}
  }

  toggleTheme() {
    this.darkMode = !this.darkMode;
    try { localStorage.setItem('secops.theme', this.darkMode ? 'dark' : 'light'); } catch {}
  }

  get mod()              { return this.cloud === 'aws' ? this.awsState[this.activeModule] : this.azureState[this.activeModule]; }
  get activeModCfg()     { return this.modules.find(m => m.id === this.activeModule)!; }
  get savedCreds()       { return this.cloud === 'aws' ? this.savedAwsCreds : this.savedAzureCreds; }
  get isAzure()          { return this.cloud === 'azure'; }
  get isOverview()       { return this.activeModule === 'overview'; }
  get cloudLabel()       { return this.cloud === 'aws' ? 'AWS' : 'Azure'; }
  get cloudIcon()        { return this.cloud === 'aws' ? '☁' : '⬡'; }
  get cloudAccent()      { return this.cloud === 'aws' ? 'var(--accent)' : 'var(--az-blue)'; }
  get moduleDesc()       { return this.cloud === 'aws' ? this.activeModCfg.awsDesc : this.activeModCfg.azureDesc; }

  // Modules that have a dashboard (excludes overview which is composed here)
  get scannableModules() { return this.modules.filter(m => m.id !== 'overview'); }

  switchCloud(c: 'aws' | 'azure') {
    this.cloud = c;
    this.showCloudMenu = false;
  }

  switchModule(id: string) {
    this.activeModule = id;
  }

  badge(id: string): string | null {
    const s = this.cloud === 'aws' ? this.awsState[id] : this.azureState[id];
    if (!s?.data) return null;
    const data = s.data as any;
    switch (id) {
      case 'discovery':  {
        const summary = (data.summary || {}) as Record<string, number>;
        const total = Object.values(summary).reduce((a: any, b: any) => ((a as number) + (b as number)), 0);
        return total.toLocaleString() + ' res';
      }
      case 'compliance': return `${data.score?.overall??0}% (${data.score?.grade||'—'})`;
      case 'risk':       return data.risk_score?.level || null;
      case 'cspm':       return `${data.total_passed??0}/${data.total_checks??0} passed`;
      case 'maturity':   return `Lvl ${data.overall_level??'-'} · ${data.overall_score??0}%`;
      case 'wellarch':   return `${data.overall_score??0}% · ${data.overall_risk??'-'}`;
    }
    return null;
  }

  isLoading(id: string): boolean {
    const s = this.cloud === 'aws' ? this.awsState[id] : this.azureState[id];
    return s?.loading ?? false;
  }

  // ── Overview aggregates (read-only, derived from existing state) ────────
  private stateFor(id: string): ModState | null {
    return (this.cloud === 'aws' ? this.awsState[id] : this.azureState[id]) || null;
  }
  healthOf(id: string): 'healthy' | 'warning' | 'critical' | 'idle' {
    const s = this.stateFor(id);
    if (!s?.data) return 'idle';
    switch (id) {
      case 'compliance': {
        const v = s.data.score?.overall ?? 0;
        return v >= 80 ? 'healthy' : v >= 60 ? 'warning' : 'critical';
      }
      case 'risk': {
        const lvl = (s.data.risk_score?.level || '').toString().toUpperCase();
        if (lvl.includes('CRIT') || lvl.includes('HIGH')) return 'critical';
        if (lvl.includes('MED')) return 'warning';
        return 'healthy';
      }
      case 'cspm': {
        const t = s.data.total_checks || 0, p = s.data.total_passed || 0;
        if (!t) return 'idle';
        const ratio = p / t;
        return ratio >= 0.8 ? 'healthy' : ratio >= 0.6 ? 'warning' : 'critical';
      }
      case 'maturity': {
        const v = s.data.overall_score ?? 0;
        return v >= 75 ? 'healthy' : v >= 50 ? 'warning' : 'critical';
      }
      case 'wellarch': {
        const r = (s.data.overall_risk || '').toString().toUpperCase();
        if (r === 'HIGH' || r === 'CRITICAL') return 'critical';
        if (r === 'MEDIUM') return 'warning';
        return 'healthy';
      }
      case 'discovery': return 'healthy';
    }
    return 'idle';
  }

  get securityScore(): number {
    const cs = this.stateFor('compliance')?.data?.score?.overall;
    const ms = this.stateFor('maturity')?.data?.overall_score;
    const ws = this.stateFor('wellarch')?.data?.overall_score;
    const vals = [cs, ms, ws].filter((v: any) => typeof v === 'number');
    if (!vals.length) return 0;
    return Math.round(vals.reduce((a:number,b:number)=>a+b,0) / vals.length);
  }
  get complianceScore(): number { return this.stateFor('compliance')?.data?.score?.overall ?? 0; }
  get riskLevel(): string { return (this.stateFor('risk')?.data?.risk_score?.level || '—').toString(); }
  get criticalFindings(): number {
    const recs = this.stateFor('maturity')?.data?.recommendations || [];
    const wrecs = this.stateFor('wellarch')?.data?.recommendations || [];
    const all = [...recs, ...wrecs];
    return all.filter((r: any) => {
      const s = (r.severity || '').toString().toUpperCase();
      return s === 'CRITICAL' || s === 'HIGH';
    }).length;
  }
  get accountId(): string {
    const candidates = ['discovery','compliance','risk','cspm','maturity','wellarch'];
    for (const id of candidates) {
      const a = this.stateFor(id)?.data?.identity?.account_id;
      if (a) return a;
    }
    return '—';
  }
  get assetCount(): number {
    const s = this.stateFor('discovery')?.data?.summary;
    if (!s) return 0;
    return (Object.values(s) as any[]).reduce((a:any,b:any)=>a+(+b||0),0);
  }
  get topIssues(): any[] {
    const out: any[] = [];
    const recs = this.stateFor('maturity')?.data?.recommendations || [];
    const wrecs = this.stateFor('wellarch')?.data?.recommendations || [];
    for (const r of recs) out.push({ title: r.title, source: 'Maturity · ' + (r.domain||''), severity: r.severity });
    for (const r of wrecs) out.push({ title: r.title, source: 'Well-Architected · ' + (r.pillar||''), severity: r.severity });
    const rank: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    out.sort((a,b)=> (rank[(a.severity||'').toUpperCase()] ?? 9) - (rank[(b.severity||'').toUpperCase()] ?? 9));
    return out.slice(0, 12);
  }
  get latestMeta(): any {
    let latest: any = null;
    for (const m of this.scannableModules) {
      const meta = this.stateFor(m.id)?.meta;
      if (meta && (!latest || (meta.timestamp || '') > (latest.timestamp || ''))) latest = meta;
    }
    return latest || { region: '—', timestamp: '—', duration: '—' };
  }

  severityBadge(sev: string): string {
    const s = (sev || '').toUpperCase();
    if (s === 'CRITICAL' || s === 'HIGH') return 'badge-red';
    if (s === 'MEDIUM') return 'badge-orange';
    if (s === 'LOW') return 'badge-yellow';
    return 'badge-neutral';
  }

  // Report modal (UI only — opens/closes; "download" generates a client-side text blob so nothing server changes)
  openReport()  { this.showReport = true; }
  closeReport() { this.showReport = false; }
  pickFormat(f: any) { this.reportFormat = f; }
  pickType(t: any)   { this.reportType = t; }
  generateReport() {
    const meta = this.latestMeta;
    const lines: string[] = [];
    lines.push(`${this.cloudLabel} SecOps — ${this.reportType.toUpperCase()} REPORT`);
    lines.push('='.repeat(60));
    lines.push(`Account: ${this.accountId}`);
    lines.push(`Region/Subscription: ${meta.region}`);
    lines.push(`Scan Date: ${meta.timestamp}`);
    lines.push(`Scan Duration: ${meta.duration}s`);
    lines.push('');
    lines.push('— SECURITY SUMMARY —');
    lines.push(`Security Score:   ${this.securityScore}%`);
    lines.push(`Compliance Score: ${this.complianceScore}%`);
    lines.push(`Risk Level:       ${this.riskLevel}`);
    lines.push(`Critical Findings: ${this.criticalFindings}`);
    lines.push(`Cloud Assets:     ${this.assetCount}`);
    lines.push('');
    lines.push('— ENVIRONMENT HEALTH —');
    for (const m of this.scannableModules) {
      lines.push(`  ${m.label.padEnd(24)} : ${this.healthOf(m.id).toUpperCase()}`);
    }
    lines.push('');
    lines.push('— TOP FINDINGS —');
    this.topIssues.forEach((i: any, idx: number) => lines.push(`  ${idx+1}. [${(i.severity||'').toUpperCase()}] ${i.title}  (${i.source})`));
    lines.push('');
    lines.push('— RECOMMENDATIONS —');
    lines.push('  • Remediate CRITICAL/HIGH findings within 7 days.');
    lines.push('  • Re-scan after remediation to verify resolution.');
    lines.push('  • Track maturity uplift over time across all pillars.');
    lines.push('');
    lines.push('— CONCLUSION —');
    lines.push('  Generated by SecOps Multi-Cloud Platform.');

    const ext = this.reportFormat === 'word' ? 'doc'
              : this.reportFormat === 'excel' ? 'csv'
              : this.reportFormat === 'pdf' ? 'pdf'
              : 'txt';
    const mime = this.reportFormat === 'pdf' ? 'application/pdf'
               : this.reportFormat === 'word' ? 'application/msword'
               : this.reportFormat === 'excel' ? 'text/csv'
               : 'text/plain';
    const filename = `secops-${this.cloud}-${this.reportType}-${Date.now()}.${ext}`;
    try {
      const blob = new Blob([lines.join('\n')], { type: mime });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = filename;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch {}
    this.closeReport();
  }

  clearError() { this.mod.error = ''; }

  // ── AWS scan ─────────────────────────────────────────────────────────────
  handleAwsScan(creds: AwsCreds) {
    this.savedAwsCreds = creds;
    const mod = this.activeModule;
    const t0  = Date.now();
    this.awsState[mod] = { ...this.awsState[mod], loading:true, error:'', data:null, creds };
    this.api.awsScan(mod, creds).subscribe({
      next: (json: any) => {
        const duration    = ((Date.now()-t0)/1000).toFixed(1);
        const regionLabel = (creds as any).allRegions ? 'All Regions' : (creds.region || 'us-east-1');
        const meta        = { duration, timestamp: new Date().toLocaleString(), region: regionLabel };
        if (json.error) this.awsState[mod] = { ...this.awsState[mod], loading:false, error:json.error };
        else            this.awsState[mod] = { ...this.awsState[mod], loading:false, data:json, meta };
      },
      error: () => {
        this.awsState[mod] = { ...this.awsState[mod], loading:false,
          error:'Cannot reach backend on http://localhost:5000. Ensure Flask server is running.' };
      }
    });
  }

  // ── Azure scan ───────────────────────────────────────────────────────────
  handleAzureScan(creds: AzureCreds) {
    this.savedAzureCreds = creds;
    const mod = this.activeModule;
    const t0  = Date.now();
    this.azureState[mod] = { ...this.azureState[mod], loading:true, error:'', data:null, creds };
    this.api.azureScan(mod, creds).subscribe({
      next: (json: any) => {
        const duration = ((Date.now()-t0)/1000).toFixed(1);
        const sub      = creds.subscriptionId || json?.subscriptions?.[0] || 'auto-detect';
        const meta     = { duration, timestamp: new Date().toLocaleString(), region: sub };
        if (json.error) this.azureState[mod] = { ...this.azureState[mod], loading:false, error:json.error };
        else            this.azureState[mod] = { ...this.azureState[mod], loading:false, data:json, meta };
      },
      error: () => {
        this.azureState[mod] = { ...this.azureState[mod], loading:false,
          error:'Cannot reach backend on http://localhost:5000. Ensure Flask server is running.' };
      }
    });
  }

  // Dispatch to correct handler based on active cloud
  handleScan(creds: any) {
    if (this.cloud === 'azure') this.handleAzureScan(creds as AzureCreds);
    else                        this.handleAwsScan(creds as AwsCreds);
  }

  loadingMessages: Record<string, Record<string, string>> = {
    aws: {
      discovery:  'Querying AWS Config across all regions…',
      compliance: 'Checking Config Rules, Security Hub, IAM…',
      risk:       'Inspector CVEs, Macie, GuardDuty, Health…',
      cspm:       'Scanning Compute, Containers, DB, Network, WAF, Secrets, CIS…',
      maturity:   'Evaluating IAM, Infra, Data, Detection, Response…',
      wellarch:   'Checking 6 pillars across your AWS account…',
    },
    azure: {
      discovery:  'Querying Azure Resource Graph across subscription…',
      compliance: 'Checking Defender, Policy, IAM, Activity Log…',
      risk:       'Scanning Defender alerts, Advisor, Monitor…',
      cspm:       'Scanning Compute, Storage, Network, KeyVault, SQL, CIS…',
      maturity:   'Evaluating Identity, Infra, Data, Detection, Response…',
      wellarch:   'Checking 5 WAF pillars across your Azure subscription…',
    },
  };

  get loadingMsg() { return this.loadingMessages[this.cloud]?.[this.activeModule] || 'Scanning…'; }
}
