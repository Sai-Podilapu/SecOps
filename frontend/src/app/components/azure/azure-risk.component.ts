import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-azure-risk',
  standalone: true,
  imports: [CommonModule],
  template: `
<div class="fade-in" style="display:flex;min-height:calc(100vh - 108px)">
  <aside style="width:210px;border-right:1px solid var(--border);background:var(--surface);padding:16px 0;position:sticky;top:108px;height:calc(100vh - 108px);overflow-y:auto;flex-shrink:0">
    <div style="padding:0 16px 14px;border-bottom:1px solid var(--border);margin-bottom:8px">
      <div style="font-size:32px;font-weight:800;font-family:var(--font-mono)" [style.color]="riskColor(data?.risk_score?.level)">
        {{data?.risk_score?.score??'—'}}
      </div>
      <div style="font-size:11px;color:var(--text-3)">Risk Score · {{data?.risk_score?.level||'—'}}</div>
      <div style="font-size:11px;color:var(--text-3);margin-top:2px">{{data?.risk_score?.total_findings||0}} findings</div>
    </div>
    <button *ngFor="let n of nav" (click)="activeTab=n.id"
      [style.border-left]="activeTab===n.id?'2px solid var(--az-blue)':'2px solid transparent'"
      [style.background]="activeTab===n.id?'var(--az-blue-dim)':'none'"
      [style.color]="activeTab===n.id?'var(--az-blue)':'var(--text-2)'"
      style="display:flex;align-items:center;gap:8px;width:100%;padding:7px 16px;border:none;cursor:pointer;font-size:13px;text-align:left">
      <span style="font-size:12px;opacity:0.7">{{n.icon}}</span>{{n.label}}
    </button>
  </aside>

  <main style="flex:1;min-width:0;padding:24px 28px;overflow-x:hidden">

    <!-- Overview -->
    <div *ngIf="activeTab==='overview'" class="fade-in" style="display:flex;flex-direction:column;gap:24px">
      <h2 style="font-size:16px;font-weight:700">Azure Risk Overview</h2>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:1px;background:var(--border);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden">
        <div *ngFor="let s of overviewStats" style="background:var(--surface);padding:14px 16px">
          <div [style.color]="s.c||''" style="font-size:20px;font-weight:700;font-family:var(--font-mono)">{{s.v??'—'}}</div>
          <div style="font-size:11px;color:var(--text-2);margin-top:3px">{{s.l}}</div>
        </div>
      </div>
      <!-- Source breakdown -->
      <div class="card" style="padding:0">
        <div class="section-title" style="padding:14px 18px 4px">Findings by Source</div>
        <div *ngFor="let s of sourceEntries(); let last=last">
          <div style="display:flex;align-items:center;gap:12px;padding:10px 18px" [style.border-bottom]="!last?'1px solid var(--border)':'none'">
            <span class="badge" [ngClass]="sourceClass(s[0])">{{s[0]}}</span>
            <div style="flex:1;height:4px;background:var(--surface-3);border-radius:2px;overflow:hidden">
              <div [style.width]="((s[1]/totalFindings)*100)+'%'" style="height:100%;background:var(--az-blue);transition:width 0.5s"></div>
            </div>
            <span style="font-family:var(--font-mono);font-size:12px">{{s[1]}}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- All Findings -->
    <div *ngIf="activeTab==='findings'" class="fade-in" style="display:flex;flex-direction:column;gap:16px">
      <h2 style="font-size:16px;font-weight:700">All Findings <span style="font-weight:400;color:var(--text-3)">({{data?.all_findings?.length||0}})</span></h2>
      <div *ngIf="!data?.all_findings?.length" class="empty">No findings — great security posture!</div>
      <div *ngIf="data?.all_findings?.length" class="card" style="padding:0">
        <div style="overflow-x:auto;max-height:calc(100vh - 280px);overflow-y:auto">
          <table>
            <thead><tr><th>Severity</th><th>Source</th><th>Title</th><th>Resource</th><th>Region</th></tr></thead>
            <tbody>
              <tr *ngFor="let f of data.all_findings">
                <td><span [ngClass]="badgeClass(f.severity)" class="badge">{{f.severity}}</span></td>
                <td><span class="badge" [ngClass]="sourceClass(f.source)">{{f.source}}</span></td>
                <td style="max-width:260px">{{f.title}}</td>
                <td><span class="mono" style="font-size:11px">{{f.resource}}</span></td>
                <td style="color:var(--text-3)">{{f.region}}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Defender Alerts -->
    <div *ngIf="activeTab==='defender'" class="fade-in" style="display:flex;flex-direction:column;gap:20px">
      <h2 style="font-size:16px;font-weight:700">Defender for Cloud Alerts</h2>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:1px;background:var(--border);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden">
        <div *ngFor="let s of defenderStats" style="background:var(--surface);padding:14px 16px">
          <div [style.color]="s.c||''" style="font-size:20px;font-weight:700;font-family:var(--font-mono)">{{s.v??'—'}}</div>
          <div style="font-size:11px;color:var(--text-2);margin-top:3px">{{s.l}}</div>
        </div>
      </div>
      <div *ngIf="data?.defender?.error" style="font-size:12px;color:var(--red);padding:12px;background:var(--red-dim);border:1px solid var(--red-b);border-radius:var(--radius)">⚠ {{data.defender.error}}</div>
    </div>

    <!-- Advisor -->
    <div *ngIf="activeTab==='advisor'" class="fade-in" style="display:flex;flex-direction:column;gap:20px">
      <h2 style="font-size:16px;font-weight:700">Azure Advisor Security</h2>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:1px;background:var(--border);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden">
        <div *ngFor="let s of [{l:'Total Recs',v:data?.advisor?.total,a:true},{l:'High Impact',v:data?.advisor?.high_impact}]"
          style="background:var(--surface);padding:14px 16px">
          <div [style.color]="s.a?'var(--az-blue)':''" style="font-size:20px;font-weight:700;font-family:var(--font-mono)">{{s.v??'—'}}</div>
          <div style="font-size:11px;color:var(--text-2);margin-top:3px">{{s.l}}</div>
        </div>
      </div>
      <div *ngIf="data?.advisor?.findings?.length" class="card" style="padding:0">
        <div style="overflow-x:auto;max-height:480px;overflow-y:auto">
          <table>
            <thead><tr><th>Severity</th><th>Title</th><th>Resource</th></tr></thead>
            <tbody>
              <tr *ngFor="let f of data.advisor.findings">
                <td><span [ngClass]="badgeClass(f.severity)" class="badge">{{f.severity}}</span></td>
                <td>{{f.title}}</td>
                <td><span class="mono" style="font-size:11px">{{f.resource}}</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
      <div *ngIf="data?.advisor?.error" style="font-size:12px;color:var(--red)">⚠ {{data.advisor.error}}</div>
    </div>

  </main>
</div>
  `,
})
export class AzureRiskComponent {
  @Input() data: any;
  @Input() meta: any;
  activeTab = 'overview';

  nav = [
    {id:'overview',  label:'Overview',         icon:'★'},
    {id:'findings',  label:'All Findings',     icon:'◈'},
    {id:'defender',  label:'Defender Alerts',  icon:'🛡'},
    {id:'advisor',   label:'Advisor',          icon:'◉'},
  ];

  riskColor(lvl: string) {
    return lvl==='CRITICAL'?'var(--red)':lvl==='HIGH'?'var(--orange)':lvl==='MEDIUM'?'var(--yellow)':'var(--green)';
  }
  badgeClass(sev: string) {
    const m: any = {CRITICAL:'badge-red',HIGH:'badge-orange',MEDIUM:'badge-yellow',LOW:'badge-neutral'};
    return 'badge ' + (m[sev] || 'badge-neutral');
  }
  sourceClass(src: string) {
    const m: any = {Defender:'badge-purple',Advisor:'badge-cyan',Monitor:'badge-orange'};
    return m[src] || 'badge-neutral';
  }
  sourceEntries(): [string, number][] {
    return Object.entries(this.data?.summary?.source_counts || {}) as [string, number][];
  }
  get totalFindings() { return this.data?.risk_score?.total_findings || 1; }
  get overviewStats() {
    const sev = this.data?.summary?.severity_counts || {};
    return [
      {l:'Risk Score',  v:this.data?.risk_score?.score,   c:this.riskColor(this.data?.risk_score?.level)},
      {l:'Critical',    v:sev['CRITICAL']||0,              c:'var(--red)'},
      {l:'High',        v:sev['HIGH']||0,                  c:'var(--orange)'},
      {l:'Medium',      v:sev['MEDIUM']||0,                c:'var(--yellow)'},
      {l:'Low',         v:sev['LOW']||0,                   c:''},
      {l:'Total',       v:this.data?.risk_score?.total_findings, c:''},
    ];
  }
  get defenderStats() {
    const sev = this.data?.defender?.severity_counts || {};
    return [
      {l:'Total Alerts', v:this.data?.defender?.total,    c:'var(--az-blue)'},
      {l:'Critical',     v:sev['CRITICAL']||0,             c:'var(--red)'},
      {l:'High',         v:sev['HIGH']||0,                 c:'var(--orange)'},
      {l:'Medium',       v:sev['MEDIUM']||0,               c:'var(--yellow)'},
    ];
  }
}
