import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-azure-wellarch',
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
        <text x="50" y="55" text-anchor="middle" font-family="var(--font-mono)" font-size="18" font-weight="700" [attr.fill]="overallColor">{{data?.overall_score||0}}%</text>
      </svg>
      <div style="text-align:center;font-size:11px;color:var(--text-3)">WAF Score</div>
      <div style="text-align:center;font-size:11px;margin-top:3px">
        <span class="badge badge-sm" [ngClass]="riskBadge(data?.overall_risk)">{{data?.overall_risk||'—'}} RISK</span>
      </div>
    </div>
    <div style="padding:0 16px 14px;border-bottom:1px solid var(--border);margin-bottom:8px">
      <div *ngFor="let key of pillarOrder" (click)="activePillar=key;activeTab='pillar'"
        style="display:flex;align-items:center;justify-content:space-between;padding:5px 0;cursor:pointer">
        <span style="font-size:12px;color:var(--text-2)">{{pillarIcons[key]}} {{data?.pillars?.[key]?.label||key}}</span>
        <span class="badge badge-sm mono" [ngClass]="scoreClass(data?.pillars?.[key]?.score)">{{data?.pillars?.[key]?.score??'—'}}%</span>
      </div>
    </div>
    <button (click)="activeTab='overview'"
      [style.border-left]="activeTab==='overview'?'2px solid var(--az-blue)':'2px solid transparent'"
      [style.background]="activeTab==='overview'?'var(--az-blue-dim)':'none'"
      [style.color]="activeTab==='overview'?'var(--az-blue)':'var(--text-2)'"
      style="display:flex;align-items:center;gap:8px;width:100%;padding:7px 16px;border:none;cursor:pointer;font-size:13px;text-align:left">
      <span style="opacity:0.7">◈</span>Overview
    </button>
    <button (click)="activeTab='pillar'"
      [style.border-left]="activeTab==='pillar'?'2px solid var(--az-blue)':'2px solid transparent'"
      [style.background]="activeTab==='pillar'?'var(--az-blue-dim)':'none'"
      [style.color]="activeTab==='pillar'?'var(--az-blue)':'var(--text-2)'"
      style="display:flex;align-items:center;gap:8px;width:100%;padding:7px 16px;border:none;cursor:pointer;font-size:13px;text-align:left">
      <span style="opacity:0.7">◉</span>Pillar Detail
    </button>
  </aside>

  <main style="flex:1;min-width:0;padding:24px 28px;overflow-x:hidden">

    <!-- Overview -->
    <div *ngIf="activeTab==='overview'" class="fade-in" style="display:flex;flex-direction:column;gap:24px">
      <h2 style="font-size:16px;font-weight:700">Azure Well-Architected Framework</h2>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:16px">
        <div *ngFor="let key of pillarOrder" class="card" style="padding:16px;cursor:pointer" (click)="activePillar=key;activeTab='pillar'">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
            <span style="font-size:18px">{{pillarIcons[key]}}</span>
            <span class="badge badge-sm" [ngClass]="riskBadge(data?.pillars?.[key]?.risk)">{{data?.pillars?.[key]?.risk||'—'}}</span>
          </div>
          <div style="font-size:13px;font-weight:600;margin-bottom:6px">{{data?.pillars?.[key]?.label||key}}</div>
          <div style="font-size:24px;font-weight:800;font-family:var(--font-mono);margin-bottom:8px" [style.color]="scoreColor(data?.pillars?.[key]?.score)">
            {{data?.pillars?.[key]?.score??'—'}}%
          </div>
          <div style="height:4px;background:var(--surface-3);border-radius:2px;overflow:hidden">
            <div [style.width]="(data?.pillars?.[key]?.score||0)+'%'" [style.background]="scoreColor(data?.pillars?.[key]?.score)" style="height:100%;transition:width 0.5s"></div>
          </div>
          <div style="font-size:11px;color:var(--text-3);margin-top:6px">
            {{data?.pillars?.[key]?.passed||0}} pass / {{data?.pillars?.[key]?.failed||0}} fail
          </div>
        </div>
      </div>
    </div>

    <!-- Pillar Detail -->
    <div *ngIf="activeTab==='pillar'" class="fade-in" style="display:flex;flex-direction:column;gap:20px">
      <div style="display:flex;align-items:center;gap:12px">
        <span style="font-size:20px">{{pillarIcons[activePillar]}}</span>
        <h2 style="font-size:16px;font-weight:700">{{data?.pillars?.[activePillar]?.label||activePillar}}</h2>
        <span class="badge" [ngClass]="riskBadge(data?.pillars?.[activePillar]?.risk)">{{data?.pillars?.[activePillar]?.risk||'—'}} RISK</span>
      </div>
      <div *ngIf="data?.pillars?.[activePillar]?.error" style="font-size:12px;color:var(--red);padding:12px;background:var(--red-dim);border:1px solid var(--red-b);border-radius:var(--radius)">
        ⚠ {{data.pillars[activePillar].error}}
      </div>
      <div *ngIf="data?.pillars?.[activePillar]?.checks?.length" class="card" style="padding:0">
        <div *ngFor="let c of data?.pillars?.[activePillar]?.checks; let last=last">
          <div style="display:flex;align-items:center;justify-content:space-between;padding:11px 18px" [style.border-bottom]="!last?'1px solid var(--border)':'none'">
            <div style="flex:1;padding-right:12px">
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
      <!-- Navigate between pillars -->
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button *ngFor="let key of pillarOrder" (click)="activePillar=key"
          [style.background]="activePillar===key?'var(--az-blue-dim)':'var(--surface)'"
          [style.color]="activePillar===key?'var(--az-blue)':'var(--text-2)'"
          [style.border]="activePillar===key?'1px solid var(--az-blue)':'1px solid var(--border)'"
          style="padding:5px 12px;border-radius:var(--radius-sm);font-size:12px;cursor:pointer">
          {{pillarIcons[key]}} {{data?.pillars?.[key]?.label||key}}
        </button>
      </div>
    </div>

  </main>
</div>
  `,
})
export class AzureWellarchComponent {
  @Input() data: any;
  @Input() meta: any;
  activeTab = 'overview';
  activePillar = 'reliability';
  pillarOrder = ['reliability','security','cost','ops','performance'];
  pillarIcons: any = {reliability:'⟳',security:'🛡',cost:'◇',ops:'⚙',performance:'⚡'};

  scoreColor(s: any) { return s>=80?'var(--green)':s>=60?'var(--yellow)':s>=40?'var(--orange)':'var(--red)'; }
  scoreClass(s: any) { return s>=80?'badge-green':s>=60?'badge-yellow':s>=40?'badge-orange':'badge-red'; }
  riskBadge(r: string) {
    return r==='CRITICAL'?'badge-red':r==='HIGH'?'badge-orange':r==='MEDIUM'?'badge-yellow':'badge-green';
  }
  badgeClass(sev: string) {
    return sev==='CRITICAL'?'badge-red':sev==='HIGH'?'badge-orange':sev==='MEDIUM'?'badge-yellow':'badge-neutral';
  }
  get overallColor() {
    const s = this.data?.overall_score||0;
    return this.scoreColor(s);
  }
  get circumference() { return 2*Math.PI*42; }
  get dashArray()     { return ((this.data?.overall_score||0)/100)*this.circumference; }
}
