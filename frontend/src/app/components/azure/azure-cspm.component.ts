import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-azure-cspm',
  standalone: true,
  imports: [CommonModule],
  template: `
<div class="fade-in" style="display:flex;min-height:calc(100vh - 108px)">
  <aside style="width:210px;border-right:1px solid var(--border);background:var(--surface);padding:16px 0;position:sticky;top:108px;height:calc(100vh - 108px);overflow-y:auto;flex-shrink:0">
    <div style="padding:0 16px 14px;border-bottom:1px solid var(--border);margin-bottom:8px">
      <svg viewBox="0 0 100 100" width="68" height="68" style="display:block;margin:0 auto 4px">
        <circle cx="50" cy="50" r="42" fill="none" stroke="var(--border)" stroke-width="7"/>
        <circle cx="50" cy="50" r="42" fill="none" stroke="var(--az-blue)" stroke-width="7"
          [attr.stroke-dasharray]="dashArray + ' ' + circumference"
          [attr.stroke-dashoffset]="circumference/4"
          stroke-linecap="round" style="transition:stroke-dasharray 0.6s ease"/>
        <text x="50" y="55" text-anchor="middle" font-family="var(--font-mono)" font-size="18" font-weight="700" fill="var(--az-blue)">{{data?.overall_score||0}}%</text>
      </svg>
      <div style="text-align:center;font-size:11px;color:var(--text-3)">Overall CSPM Score</div>
      <div style="text-align:center;font-size:11px;color:var(--text-3);margin-top:2px">{{data?.total_failed||0}} failures / {{data?.total_checks||0}} checks</div>
    </div>
    <button *ngFor="let t of tabs" (click)="activeTab=t.id"
      [style.border-left]="activeTab===t.id?'2px solid var(--az-blue)':'2px solid transparent'"
      [style.background]="activeTab===t.id?'var(--az-blue-dim)':'none'"
      [style.color]="activeTab===t.id?'var(--az-blue)':'var(--text-2)'"
      style="display:flex;align-items:center;justify-content:space-between;width:100%;padding:7px 16px;border:none;cursor:pointer;font-size:13px;text-align:left">
      <div style="display:flex;align-items:center;gap:8px">
        <span style="font-size:12px;opacity:0.7">{{modIcons[t.id]||'◈'}}</span>{{t.label}}
      </div>
      <span *ngIf="t.score!=null" class="badge badge-sm mono" [ngClass]="badgeClass2(t.score)">{{t.score}}%</span>
    </button>
  </aside>

  <main style="flex:1;min-width:0;padding:24px 28px;overflow-x:hidden">

    <!-- Overview -->
    <div *ngIf="activeTab==='overview'" class="fade-in" style="display:flex;flex-direction:column;gap:24px">
      <h2 style="font-size:16px;font-weight:700">Azure CSPM Overview</h2>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:16px">
        <div *ngFor="let key of modOrder" class="card" style="padding:14px 16px;cursor:pointer" (click)="activeTab=key">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px">
            <span style="font-size:16px">{{modIcons[key]}}</span>
            <span class="badge badge-sm mono" [ngClass]="badgeClass2(data?.modules?.[key]?.score)">{{data?.modules?.[key]?.score??'—'}}%</span>
          </div>
          <div style="font-size:13px;font-weight:600;margin-bottom:4px">{{data?.modules?.[key]?.label||key}}</div>
          <div style="font-size:11px;color:var(--text-3)">{{data?.modules?.[key]?.failed||0}} fail / {{data?.modules?.[key]?.total_checks||0}} checks</div>
          <div style="margin-top:8px;height:3px;background:var(--surface-3);border-radius:2px;overflow:hidden">
            <div [style.width]="(data?.modules?.[key]?.score||0)+'%'" [style.background]="scoreColor(data?.modules?.[key]?.score)" style="height:100%;transition:width 0.5s"></div>
          </div>
        </div>
      </div>
    </div>

    <!-- Failures -->
    <div *ngIf="activeTab==='failures'" class="fade-in" style="display:flex;flex-direction:column;gap:16px">
      <h2 style="font-size:16px;font-weight:700">Top Failures <span style="font-weight:400;color:var(--text-3)">({{data?.top_failures?.length||0}})</span></h2>
      <div *ngIf="!data?.top_failures?.length" class="empty">No failures — excellent posture!</div>
      <div *ngIf="data?.top_failures?.length" class="card" style="padding:0">
        <div style="overflow-x:auto;max-height:calc(100vh - 260px);overflow-y:auto">
          <table>
            <thead><tr><th>Severity</th><th>Check</th><th>Module</th><th>Detail</th></tr></thead>
            <tbody>
              <tr *ngFor="let f of data.top_failures">
                <td><span class="badge" [ngClass]="badgeClass(f.severity)">{{f.severity}}</span></td>
                <td style="max-width:220px">{{f.check}}</td>
                <td><span class="badge badge-neutral">{{f.module}}</span></td>
                <td style="color:var(--text-2);max-width:200px">{{f.detail}}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Module detail -->
    <div *ngFor="let key of modOrder">
      <div *ngIf="activeTab===key" class="fade-in" style="display:flex;flex-direction:column;gap:20px">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <h2 style="font-size:16px;font-weight:700">{{data?.modules?.[key]?.label||key}}</h2>
          <span class="badge badge-sm mono" [ngClass]="badgeClass2(data?.modules?.[key]?.score)">{{data?.modules?.[key]?.score}}% score</span>
        </div>
        <div *ngIf="data?.modules?.[key]?.error" style="font-size:12px;color:var(--red);padding:12px;background:var(--red-dim);border:1px solid var(--red-b);border-radius:var(--radius)">⚠ {{data.modules[key].error}}</div>
        <div *ngIf="data?.modules?.[key]?.checks?.length" class="card" style="padding:0">
          <div *ngFor="let c of data?.modules?.[key]?.checks; let last=last">
            <div style="display:flex;align-items:center;justify-content:space-between;padding:11px 18px" [style.border-bottom]="!last?'1px solid var(--border)':'none'">
              <div style="flex:1;min-width:0;padding-right:12px">
                <div style="font-size:12px;font-weight:500">{{c.check}}</div>
                <div style="font-size:11px;color:var(--text-3);margin-top:2px">{{c.detail}}</div>
              </div>
              <div style="display:flex;gap:8px;flex-shrink:0">
                <span *ngIf="c.status==='FAIL'" class="badge badge-sm" [ngClass]="badgeClass(c.severity)">{{c.severity}}</span>
                <span class="badge badge-sm" [ngClass]="c.status==='PASS'?'badge-green':'badge-red'">{{c.status}}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

  </main>
</div>
  `,
})
export class AzureCspmComponent {
  @Input() data: any;
  @Input() meta: any;
  activeTab = 'overview';
  modOrder = ['compute','storage','network','keyvault','database','cis'];
  modIcons: any = {compute:'⚙',storage:'◻',network:'⬡',keyvault:'🔑',database:'◈',cis:'📋'};
  expanded: any = {};

  scoreColor(s: any) { return s>=80?'var(--green)':s>=60?'var(--yellow)':s>=40?'var(--orange)':'var(--red)'; }
  badgeClass(sev: string) { return sev==='CRITICAL'?'badge-red':sev==='HIGH'?'badge-orange':sev==='MEDIUM'?'badge-yellow':'badge-neutral'; }
  badgeClass2(s: any)    { return s>=80?'badge-green':s>=60?'badge-yellow':s>=40?'badge-orange':'badge-red'; }

  get tabs() {
    const t: any[] = [{id:'overview',label:'Overview',score:null},{id:'failures',label:'Failures ('+(this.data?.top_failures?.length||0)+')',score:null}];
    for (const k of this.modOrder) if (this.data?.modules?.[k]) t.push({id:k,label:this.data.modules[k].label,score:this.data.modules[k].score});
    return t;
  }
  get circumference() { return 2 * Math.PI * 42; }
  get dashArray()     { return ((this.data?.overall_score||0)/100)*this.circumference; }
}
