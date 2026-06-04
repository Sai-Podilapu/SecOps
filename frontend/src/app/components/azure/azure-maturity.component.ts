import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-azure-maturity',
  standalone: true,
  imports: [CommonModule],
  template: `
<div class="fade-in" style="display:flex;min-height:calc(100vh - 108px)">
  <aside style="width:210px;border-right:1px solid var(--border);background:var(--surface);padding:16px 0;position:sticky;top:108px;height:calc(100vh - 108px);overflow-y:auto;flex-shrink:0">
    <div style="padding:0 16px 14px;border-bottom:1px solid var(--border);margin-bottom:8px">
      <svg viewBox="0 0 100 100" width="68" height="68" style="display:block;margin:0 auto 4px">
        <circle cx="50" cy="50" r="42" fill="none" stroke="var(--border)" stroke-width="7"/>
        <circle cx="50" cy="50" r="42" fill="none" [attr.stroke]="overallColor" stroke-width="7"
          [attr.stroke-dasharray]="dashArray+' '+circumference"
          [attr.stroke-dashoffset]="circumference/4"
          stroke-linecap="round" style="transition:stroke-dasharray 0.6s ease"/>
        <text x="50" y="50" text-anchor="middle" font-family="var(--font-mono)" font-size="18" font-weight="700" [attr.fill]="overallColor">{{data?.overall_score||0}}</text>
        <text x="50" y="64" text-anchor="middle" font-family="var(--font-sans)" font-size="9" fill="var(--text-3)">Level {{data?.overall_level||1}}</text>
      </svg>
      <div style="text-align:center;font-size:11px;color:var(--text-3)">Maturity Score</div>
    </div>
    <div style="padding:0 16px 14px;border-bottom:1px solid var(--border);margin-bottom:8px">
      <div *ngFor="let key of domainOrder" (click)="activeDomain=key;activeTab='domain'"
        style="display:flex;align-items:center;justify-content:space-between;padding:5px 0;cursor:pointer">
        <span style="font-size:12px;color:var(--text-2)">{{data?.domains?.[key]?.label||key}}</span>
        <div style="display:flex;align-items:center;gap:6px">
          <div style="width:32px;height:3px;background:var(--surface-3);border-radius:2px;overflow:hidden">
            <div [style.width]="(data?.domains?.[key]?.score||0)+'%'" [style.background]="color(data?.domains?.[key])" style="height:100%"></div>
          </div>
          <span style="font-family:var(--font-mono);font-size:10px;color:var(--text-3)">L{{data?.domains?.[key]?.level||1}}</span>
        </div>
      </div>
    </div>
    <button (click)="activeTab='overview'"
      [style.border-left]="activeTab==='overview'?'2px solid var(--az-blue)':'2px solid transparent'"
      [style.background]="activeTab==='overview'?'var(--az-blue-dim)':'none'"
      [style.color]="activeTab==='overview'?'var(--az-blue)':'var(--text-2)'"
      style="display:flex;align-items:center;gap:8px;width:100%;padding:7px 16px;border:none;cursor:pointer;font-size:13px;text-align:left">
      <span style="font-size:12px;opacity:0.7">◈</span>Overview
    </button>
    <button (click)="activeTab='domain'"
      [style.border-left]="activeTab==='domain'?'2px solid var(--az-blue)':'2px solid transparent'"
      [style.background]="activeTab==='domain'?'var(--az-blue-dim)':'none'"
      [style.color]="activeTab==='domain'?'var(--az-blue)':'var(--text-2)'"
      style="display:flex;align-items:center;gap:8px;width:100%;padding:7px 16px;border:none;cursor:pointer;font-size:13px;text-align:left">
      <span style="font-size:12px;opacity:0.7">◉</span>Domain Detail
    </button>
  </aside>

  <main style="flex:1;min-width:0;padding:24px 28px;overflow-x:hidden">

    <!-- Overview -->
    <div *ngIf="activeTab==='overview'" class="fade-in" style="display:flex;flex-direction:column;gap:24px">
      <h2 style="font-size:16px;font-weight:700">Azure Security Maturity</h2>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:16px">
        <div *ngFor="let key of domainOrder" class="card" style="padding:16px;cursor:pointer" (click)="activeDomain=key;activeTab='domain'">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
            <span style="font-size:13px;font-weight:600">{{data?.domains?.[key]?.label||key}}</span>
            <span class="badge badge-sm" [ngClass]="levelBadge(data?.domains?.[key]?.level)">L{{data?.domains?.[key]?.level||1}}</span>
          </div>
          <div style="font-size:24px;font-weight:800;font-family:var(--font-mono);margin-bottom:8px" [style.color]="color(data?.domains?.[key])">{{data?.domains?.[key]?.score||0}}%</div>
          <div style="height:4px;background:var(--surface-3);border-radius:2px;overflow:hidden">
            <div [style.width]="(data?.domains?.[key]?.score||0)+'%'" [style.background]="color(data?.domains?.[key])" style="height:100%;transition:width 0.5s"></div>
          </div>
          <div style="font-size:11px;color:var(--text-3);margin-top:6px">{{data?.domains?.[key]?.passed||0}} passed / {{(data?.domains?.[key]?.checks||[]).length}} checks</div>
        </div>
      </div>
      <!-- Level scale -->
      <div class="card" style="padding:16px">
        <div class="section-title" style="margin-bottom:12px">Maturity Levels</div>
        <div style="display:flex;gap:12px;flex-wrap:wrap">
          <div *ngFor="let lv of [1,2,3,4,5]" style="display:flex;align-items:center;gap:6px">
            <span class="badge badge-sm" [ngClass]="levelBadge(lv)">L{{lv}}</span>
            <span style="font-size:11px;color:var(--text-2)">{{levelLabels[lv]}}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Domain Detail -->
    <div *ngIf="activeTab==='domain'" class="fade-in" style="display:flex;flex-direction:column;gap:20px">
      <div style="display:flex;align-items:center;gap:12px">
        <h2 style="font-size:16px;font-weight:700">{{data?.domains?.[activeDomain]?.label||activeDomain}}</h2>
        <span class="badge" [ngClass]="levelBadge(data?.domains?.[activeDomain]?.level)">Level {{data?.domains?.[activeDomain]?.level||1}} — {{levelLabels[data?.domains?.[activeDomain]?.level||1]}}</span>
      </div>
      <div *ngIf="data?.domains?.[activeDomain]?.error" style="font-size:12px;color:var(--red)">⚠ {{data.domains[activeDomain].error}}</div>
      <div *ngIf="data?.domains?.[activeDomain]?.checks?.length" class="card" style="padding:0">
        <div *ngFor="let c of data?.domains?.[activeDomain]?.checks; let last=last">
          <div style="display:flex;align-items:center;justify-content:space-between;padding:11px 18px" [style.border-bottom]="!last?'1px solid var(--border)':'none'">
            <div style="flex:1;padding-right:12px">
              <div style="font-size:12px;font-weight:500">{{c.check}}</div>
              <div style="font-size:11px;color:var(--text-3);margin-top:2px">{{c.finding}}</div>
            </div>
            <div style="display:flex;gap:8px;flex-shrink:0">
              <span *ngIf="c.status==='FAIL'" class="badge badge-sm" [ngClass]="badgeClass(c.severity)">{{c.severity}}</span>
              <span class="badge badge-sm" [ngClass]="c.status==='PASS'?'badge-green':'badge-red'">{{c.status}}</span>
            </div>
          </div>
        </div>
      </div>
    </div>

  </main>
</div>
  `,
})
export class AzureMaturityComponent {
  @Input() data: any;
  @Input() meta: any;
  activeTab = 'overview';
  activeDomain = 'identity';
  domainOrder = ['identity','infrastructure','data','detection','response'];

  colorMap: any = {green:'var(--green)',cyan:'var(--cyan)',yellow:'var(--yellow)',orange:'var(--orange)',red:'var(--red)'};
  color(d: any) { return this.colorMap[d?.color]||'var(--text-2)'; }
  get overallColor() { return this.colorMap[this.data?.overall_color]||'var(--text-2)'; }
  get circumference() { return 2*Math.PI*42; }
  get dashArray()     { return ((this.data?.overall_score||0)/100)*this.circumference; }
  levelLabels: any = {1:'Initial',2:'Developing',3:'Defined',4:'Managed',5:'Optimized'};
  levelBadge(l: number) { return l>=4?'badge-green':l===3?'badge-yellow':l===2?'badge-orange':'badge-red'; }
  badgeClass(sev: string) { return sev==='CRITICAL'?'badge-red':sev==='HIGH'?'badge-orange':sev==='MEDIUM'?'badge-yellow':'badge-neutral'; }
}
