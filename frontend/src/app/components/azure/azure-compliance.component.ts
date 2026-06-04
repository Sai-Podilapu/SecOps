import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-azure-compliance',
  standalone: true,
  imports: [CommonModule],
  template: `
<div class="fade-in" style="display:flex;min-height:calc(100vh - 108px)">
  <aside style="width:210px;border-right:1px solid var(--border);background:var(--surface);padding:16px 0;position:sticky;top:108px;height:calc(100vh - 108px);overflow-y:auto;flex-shrink:0">
    <div style="padding:0 16px 14px;border-bottom:1px solid var(--border);margin-bottom:8px">
      <div style="font-size:32px;font-weight:800;font-family:var(--font-mono)" [style.color]="scoreColor(data?.score?.overall)">
        {{data?.score?.overall??'—'}}%
      </div>
      <div style="font-size:11px;color:var(--text-3)">Overall Score · Grade {{data?.score?.grade||'—'}}</div>
      <div *ngIf="meta" style="font-size:10px;color:var(--text-3);margin-top:4px">{{meta.duration}}s scan</div>
    </div>
    <button *ngFor="let n of nav" (click)="activeTab=n.id"
      [style.border-left]="activeTab===n.id?'2px solid var(--az-blue)':'2px solid transparent'"
      [style.background]="activeTab===n.id?'var(--az-blue-dim)':'none'"
      [style.color]="activeTab===n.id?'var(--az-blue)':'var(--text-2)'"
      style="display:flex;align-items:center;justify-content:space-between;width:100%;padding:7px 16px;border:none;cursor:pointer;font-size:13px;text-align:left">
      <div style="display:flex;align-items:center;gap:8px">
        <span style="font-size:12px;opacity:0.7">{{n.icon}}</span>{{n.label}}
      </div>
      <span *ngIf="tabScore(n.id)!=null" class="badge badge-sm mono"
        [ngClass]="badgeType(tabScore(n.id))">{{tabScore(n.id)}}%</span>
    </button>
  </aside>

  <main style="flex:1;min-width:0;padding:24px 28px;overflow-x:hidden">

    <!-- Overview -->
    <div *ngIf="activeTab==='overview'" class="fade-in" style="display:flex;flex-direction:column;gap:24px">
      <h2 style="font-size:16px;font-weight:700">Azure Compliance Overview</h2>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:1px;background:var(--border);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden">
        <div *ngFor="let s of [{l:'Total Checks',v:data?.summary?.total_checks,a:false},{l:'Passed',v:data?.summary?.passed_checks,a:false},{l:'Failed',v:data?.summary?.failed_checks,a:false}]"
          style="background:var(--surface);padding:14px 16px">
          <div [style.color]="s.a?'var(--az-blue)':''" style="font-size:20px;font-weight:700;font-family:var(--font-mono)">{{s.v??'—'}}</div>
          <div style="font-size:11px;color:var(--text-2);margin-top:3px">{{s.l}}</div>
        </div>
      </div>
      <div class="card" style="padding:0">
        <div class="section-title" style="padding:14px 18px 4px">Scanner Scores</div>
        <div *ngFor="let s of sections; let last=last">
          <div style="display:flex;align-items:center;justify-content:space-between;padding:11px 18px" [style.border-bottom]="!last?'1px solid var(--border)':'none'">
            <span style="font-size:13px">{{s.label}}</span>
            <div style="display:flex;align-items:center;gap:12px">
              <div style="width:80px;height:4px;background:var(--surface-3);border-radius:2px;overflow:hidden">
                <div [style.width]="(data?.[s.key]?.score||0)+'%'" [style.background]="scoreColor(data?.[s.key]?.score)" style="height:100%;transition:width 0.5s"></div>
              </div>
              <span class="badge badge-sm mono" [ngClass]="badgeType(data?.[s.key]?.score)">{{data?.[s.key]?.score??'—'}}%</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Defender -->
    <div *ngIf="activeTab==='defender'" class="fade-in" style="display:flex;flex-direction:column;gap:20px">
      <h2 style="font-size:16px;font-weight:700">Defender for Cloud</h2>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:1px;background:var(--border);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden">
        <div *ngFor="let s of [{l:'Secure Score',v:data?.defender?.secure_score,a:true},{l:'Max Score',v:data?.defender?.max_score},{l:'Recommendations',v:data?.defender?.recommendations?.length}]"
          style="background:var(--surface);padding:14px 16px">
          <div [style.color]="s.a?'var(--az-blue)':''" style="font-size:20px;font-weight:700;font-family:var(--font-mono)">{{s.v??'—'}}</div>
          <div style="font-size:11px;color:var(--text-2);margin-top:3px">{{s.l}}</div>
        </div>
      </div>
      <div *ngIf="data?.defender?.recommendations?.length" class="card" style="padding:0">
        <div class="section-title" style="padding:14px 18px 4px">Recommendations</div>
        <div style="overflow-x:auto;max-height:480px;overflow-y:auto">
          <table>
            <thead><tr><th>Name</th><th>Status</th><th>Severity</th></tr></thead>
            <tbody>
              <tr *ngFor="let r of data?.defender?.recommendations?.slice(0,50)">
                <td>{{r.name}}</td>
                <td><span class="badge" [ngClass]="r.status==='Healthy'?'badge-green':'badge-yellow'">{{r.status}}</span></td>
                <td><span class="badge" [ngClass]="sevBadge(r.severity)">{{r.severity}}</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Policy -->
    <div *ngIf="activeTab==='policy'" class="fade-in" style="display:flex;flex-direction:column;gap:20px">
      <h2 style="font-size:16px;font-weight:700">Azure Policy Compliance</h2>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:1px;background:var(--border);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden">
        <div *ngFor="let s of [{l:'Compliant',v:data?.policy?.compliant,a:true},{l:'Non-Compliant',v:data?.policy?.non_compliant},{l:'Total',v:data?.policy?.total_checks}]"
          style="background:var(--surface);padding:14px 16px">
          <div [style.color]="s.a?'var(--green)':''" style="font-size:20px;font-weight:700;font-family:var(--font-mono)">{{s.v??'—'}}</div>
          <div style="font-size:11px;color:var(--text-2);margin-top:3px">{{s.l}}</div>
        </div>
      </div>
      <div *ngIf="data?.policy?.policies?.length" class="card" style="padding:0">
        <div style="overflow-x:auto;max-height:480px;overflow-y:auto">
          <table>
            <thead><tr><th>Policy</th><th>Resource</th><th>Status</th></tr></thead>
            <tbody>
              <tr *ngFor="let p of data?.policy?.policies?.slice(0,100)">
                <td style="max-width:200px">{{p.policy}}</td>
                <td><span class="mono" style="font-size:11px">{{p.resource}}</span></td>
                <td><span class="badge" [ngClass]="p.status==='COMPLIANT'?'badge-green':'badge-red'">{{p.status}}</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- IAM -->
    <div *ngIf="activeTab==='iam'" class="fade-in" style="display:flex;flex-direction:column;gap:20px">
      <h2 style="font-size:16px;font-weight:700">IAM / RBAC Compliance</h2>
      <div *ngIf="data?.iam_compliance?.checks?.length" class="card" style="padding:0">
        <div *ngFor="let c of data?.iam_compliance?.checks; let last=last">
          <div style="display:flex;align-items:center;justify-content:space-between;padding:12px 18px" [style.border-bottom]="!last?'1px solid var(--border)':'none'">
            <div>
              <div style="font-size:12px;font-weight:500">{{c.check}}</div>
              <div style="font-size:11px;color:var(--text-3);margin-top:2px">{{c.detail}}</div>
            </div>
            <span class="badge" [ngClass]="c.status==='PASS'?'badge-green':'badge-red'">{{c.status}}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Activity Log -->
    <div *ngIf="activeTab==='activity'" class="fade-in" style="display:flex;flex-direction:column;gap:20px">
      <h2 style="font-size:16px;font-weight:700">Activity Log & Diagnostics</h2>
      <div *ngIf="data?.activity_log?.checks?.length" class="card" style="padding:0">
        <div *ngFor="let c of data?.activity_log?.checks; let last=last">
          <div style="display:flex;align-items:center;justify-content:space-between;padding:12px 18px" [style.border-bottom]="!last?'1px solid var(--border)':'none'">
            <div>
              <div style="font-size:12px;font-weight:500">{{c.check}}</div>
              <div style="font-size:11px;color:var(--text-3);margin-top:2px">{{c.detail}}</div>
            </div>
            <span class="badge" [ngClass]="c.status==='PASS'?'badge-green':'badge-red'">{{c.status}}</span>
          </div>
        </div>
      </div>
    </div>

  </main>
</div>
  `,
})
export class AzureComplianceComponent {
  @Input() data: any;
  @Input() meta: any;
  activeTab = 'overview';

  scoreColor(s: any) { return s==null?'var(--text-3)':s>=80?'var(--green)':s>=60?'var(--yellow)':'var(--red)'; }
  badgeType(s: any)  { return s==null?'badge-neutral':s>=80?'badge-green':s>=60?'badge-yellow':'badge-red'; }
  sevBadge(s: string){ return s?.toLowerCase()==='high'?'badge-orange':s?.toLowerCase()==='medium'?'badge-yellow':'badge-neutral'; }

  sections = [
    {label:'Defender for Cloud', key:'defender'},
    {label:'Azure Policy',       key:'policy'},
    {label:'IAM / RBAC',         key:'iam_compliance'},
    {label:'Activity Log',       key:'activity_log'},
  ];
  nav = [
    {id:'overview',  label:'Overview',       icon:'◈'},
    {id:'defender',  label:'Defender',       icon:'🛡'},
    {id:'policy',    label:'Policy',         icon:'◉'},
    {id:'iam',       label:'IAM / RBAC',     icon:'◎'},
    {id:'activity',  label:'Activity Log',   icon:'◇'},
  ];
  private tabKeyMap: Record<string, string> = {
    defender:'defender', policy:'policy', iam:'iam_compliance', activity:'activity_log'
  };
  tabScore(id: string): number | null {
    const key = this.tabKeyMap[id];
    return key ? (this.data?.[key]?.score ?? null) : null;
  }
}
