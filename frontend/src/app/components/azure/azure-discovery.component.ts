import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-azure-discovery',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
<div class="fade-in" style="display:flex;min-height:calc(100vh - 108px)">
  <!-- Sidebar -->
  <aside style="width:210px;border-right:1px solid var(--border);background:var(--surface);padding:16px 0;position:sticky;top:108px;height:calc(100vh - 108px);overflow-y:auto;flex-shrink:0">
    <div style="padding:0 16px 14px;border-bottom:1px solid var(--border);margin-bottom:8px">
      <div *ngFor="let item of sidebarStats" style="margin-bottom:5px">
        <div style="font-size:10px;color:var(--text-3)">{{item[0]}}</div>
        <div style="font-family:var(--font-mono);font-size:11px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{item[1]||'—'}}</div>
      </div>
      <div *ngIf="meta" style="font-size:10px;color:var(--text-3);margin-top:4px">Scanned in {{meta.duration}}s</div>
    </div>
    <button *ngFor="let tab of tabs" (click)="activeTab=tab.id"
      [style.border-left]="activeTab===tab.id?'2px solid var(--az-blue)':'2px solid transparent'"
      [style.background]="activeTab===tab.id?'var(--az-blue-dim)':'none'"
      [style.color]="activeTab===tab.id?'var(--az-blue)':'var(--text-2)'"
      style="display:flex;align-items:center;gap:8px;width:100%;padding:7px 16px;border:none;cursor:pointer;font-size:13px;text-align:left">
      <span style="font-size:12px;opacity:0.7">{{tab.icon}}</span>{{tab.label}}
    </button>
  </aside>

  <main style="flex:1;min-width:0;padding:24px 28px;overflow-x:hidden">

    <!-- Overview -->
    <div *ngIf="activeTab==='overview'" class="fade-in" style="display:flex;flex-direction:column;gap:24px">
      <div>
        <h2 style="font-size:16px;font-weight:700;margin-bottom:4px">Azure Resource Overview</h2>
        <p style="font-size:12px;color:var(--text-2)">{{meta?.timestamp}} · {{data?.scan_time}}</p>
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:1px;background:var(--border);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden">
        <div *ngFor="let s of overviewStats" style="background:var(--surface);padding:14px 16px">
          <div [style.color]="s.a?'var(--az-blue)':'inherit'" style="font-size:20px;font-weight:700;font-family:var(--font-mono);letter-spacing:-0.02em">{{s.v}}</div>
          <div style="font-size:11px;color:var(--text-2);margin-top:3px">{{s.l}}</div>
        </div>
      </div>
      <div *ngIf="topTypes.length" class="card" style="padding:0">
        <div class="section-title" style="padding:14px 18px 4px">Top Resource Types</div>
        <div *ngFor="let t of topTypes; let i=index; let last=last">
          <div style="display:flex;align-items:center;gap:12px;padding:9px 16px" [style.border-bottom]="!last?'1px solid var(--border)':'none'">
            <div style="width:24px;text-align:right;font-family:var(--font-mono);font-size:11px;color:var(--text-3);flex-shrink:0">{{i+1}}</div>
            <div style="flex:1;min-width:0">
              <div style="font-size:12px;margin-bottom:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{t[0]}}</div>
              <div style="height:3px;background:var(--surface-3);border-radius:2px;overflow:hidden">
                <div [style.width]=\"((getNumericValue(t[1])/maxCount)*100)+'%'\" style=\"height:100%;background:var(--az-blue);transition:width 0.5s\"></div>
              </div>
            </div>
            <div style="font-family:var(--font-mono);font-size:12px;font-weight:500;flex-shrink:0">{{t[1]}}</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Resource Explorer -->
    <div *ngIf="activeTab==='explorer'" class="fade-in" style="display:flex;flex-direction:column;gap:16px">
      <div>
        <h2 style="font-size:16px;font-weight:700;margin-bottom:4px">Resource Explorer</h2>
        <p style="font-size:12px;color:var(--text-2)">{{allResources.length}} total · {{filtered.length}} shown</p>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
        <input [(ngModel)]="search" (ngModelChange)="resetPage()" placeholder="Search name, type, region…"
          style="flex:1;min-width:200px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 12px;font-size:12px;color:var(--text-1);outline:none"/>
        <select [(ngModel)]="selType" (ngModelChange)="resetPage()"
          style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 10px;font-size:12px;color:var(--text-1);outline:none">
          <option value="">All types ({{allTypes.length}})</option>
          <option *ngFor="let t of allTypes" [value]="t">{{t}}</option>
        </select>
        <select [(ngModel)]="selRegion" (ngModelChange)="resetPage()"
          style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:7px 10px;font-size:12px;color:var(--text-1);outline:none">
          <option value="">All regions</option>
          <option *ngFor="let r of allRegions" [value]="r">{{r}}</option>
        </select>
      </div>
      <div *ngIf="filtered.length===0" class="empty">No resources match your filters.</div>
      <div *ngIf="filtered.length>0" style="border:1px solid var(--border);border-radius:var(--radius);overflow:hidden">
        <div style="overflow-x:auto;max-height:calc(100vh-380px);overflow-y:auto">
          <table>
            <thead><tr><th>Name</th><th>Type</th><th>Region</th><th>Resource Group</th></tr></thead>
            <tbody>
              <tr *ngFor="let r of pagedResources">
                <td><span class="mono" style="font-size:11px">{{r.resourceName}}</span></td>
                <td><span class="mono" style="font-size:11px">{{r.resourceType}}</span></td>
                <td><span class="mono" style="font-size:11px">{{r.region}}</span></td>
                <td style="color:var(--text-2)">{{r.resourceGroup}}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div *ngIf="totalPages>1" style="display:flex;align-items:center;justify-content:space-between;padding:10px 16px;border-top:1px solid var(--border);background:var(--surface)">
          <span style="font-size:11px;color:var(--text-3)">Page {{explorerPage+1}} of {{totalPages}} · {{filtered.length}} resources</span>
          <div style="display:flex;gap:6px">
            <button (click)="prevPage()" [disabled]="explorerPage===0" style="padding:4px 12px;font-size:11px;background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-1);cursor:pointer">← Prev</button>
            <button (click)="nextPage()" [disabled]="explorerPage===totalPages-1" style="padding:4px 12px;font-size:11px;background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text-1);cursor:pointer">Next →</button>
          </div>
        </div>
      </div>
    </div>

    <!-- By Resource Group -->
    <div *ngIf="activeTab==='groups'" class="fade-in" style="display:flex;flex-direction:column;gap:20px">
      <h2 style="font-size:16px;font-weight:700">By Resource Group</h2>
      <div *ngIf="!resourceGroups.length" class="empty">No resource groups found.</div>
      <div *ngFor="let rg of resourceGroups" class="card" style="padding:0">
        <div style="display:flex;justify-content:space-between;align-items:center;padding:12px 18px;border-bottom:1px solid var(--border)">
          <span class="mono" style="font-size:13px;font-weight:600">{{rg.name}}</span>
          <div style="display:flex;gap:8px;align-items:center">
            <span class="badge badge-neutral mono">{{rg.location}}</span>
            <span class="badge" [ngClass]="rg.state==='Succeeded'?'badge-green':'badge-yellow'">{{rg.state}}</span>
          </div>
        </div>
        <div style="padding:10px 18px;font-size:11px;color:var(--text-3)">
          Tags: {{rg.tags && (rg.tags | json)!=='{}' ? (rg.tags | json) : 'none'}}
        </div>
      </div>
    </div>

    <!-- Cost & Usage -->
    <div *ngIf="activeTab==='costs'" class="fade-in" style="display:flex;flex-direction:column;gap:20px">
      <div>
        <h2 style="font-size:16px;font-weight:700;margin-bottom:4px">Cost & Usage</h2>
        <p style="font-size:12px;color:var(--text-2)">Period: {{costs.period||'—'}}</p>
      </div>
      <div *ngIf="costs.error" style="padding:14px 18px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);font-size:12px;color:var(--red)">
        ⚠ Cost Management unavailable: {{costs.error}}
      </div>
      <div *ngIf="!costs.error" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:1px;background:var(--border);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden">
        <div *ngFor="let s of [{l:'Month-to-Date',v:'$'+costs.total,a:true},{l:'Services',v:costsByService.length},{l:'Regions',v:costsByRegion.length}]"
          style="background:var(--surface);padding:14px 16px">
          <div [style.color]="s.a?'var(--az-blue)':'inherit'" style="font-size:20px;font-weight:700;font-family:var(--font-mono)">{{s.v}}</div>
          <div style="font-size:11px;color:var(--text-2);margin-top:3px">{{s.l}}</div>
        </div>
      </div>
      <div *ngIf="costsByService.length" class="card" style="padding:0">
        <div class="section-title" style="padding:14px 18px 4px">Cost by Service (MTD)</div>
        <div *ngFor="let s of costsByService; let last=last">
          <div style="display:flex;align-items:center;gap:12px;padding:9px 16px" [style.border-bottom]="!last?'1px solid var(--border)':'none'">
            <div style="flex:1;min-width:0">
              <div style="font-size:12px;margin-bottom:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{{s[0]}}</div>
              <div style="height:3px;background:var(--surface-3);border-radius:2px;overflow:hidden">
                <div [style.width]=\"((getNumericValue(s[1])/maxServiceCost)*100)+'%'\" style=\"height:100%;background:var(--az-blue);transition:width 0.5s\"></div>
              </div>
            </div>
            <div style=\"font-family:var(--font-mono);font-size:12px;font-weight:500;flex-shrink:0\">\${{(getNumericValue(s[1])).toFixed(2)}}</div>
          </div>
        </div>
      </div>
    </div>

    <!-- IAM -->
    <div *ngIf="activeTab==='iam'" class="fade-in" style="display:flex;flex-direction:column;gap:20px">
      <h2 style="font-size:16px;font-weight:700">IAM / RBAC Summary</h2>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:1px;background:var(--border);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden">
        <div *ngFor="let s of iamStats" style="background:var(--surface);padding:14px 16px">
          <div style="font-size:20px;font-weight:700;font-family:var(--font-mono);color:var(--az-blue)">{{s.v}}</div>
          <div style="font-size:11px;color:var(--text-2);margin-top:3px">{{s.l}}</div>
        </div>
      </div>
      <div *ngIf="iamSum.error" style="font-size:12px;color:var(--red)">⚠ {{iamSum.error}}</div>
    </div>

  </main>
</div>
  `,
})
export class AzureDiscoveryComponent {
  @Input() data: any;
  @Input() meta: any;
  activeTab = 'overview';
  search = ''; selType = ''; selRegion = '';
  explorerPage = 0;
  readonly PAGE_SIZE = 50;

  tabs = [
    {id:'overview', label:'Overview',        icon:'◈'},
    {id:'explorer', label:'Resource Explorer',icon:'⊞'},
    {id:'groups',   label:'Resource Groups',  icon:'◎'},
    {id:'costs',    label:'Cost & Usage',     icon:'◇'},
    {id:'iam',      label:'IAM / RBAC',       icon:'◉'},
  ];

  get identity()   { return this.data?.identity || {}; }
  get iamSum()     { return this.data?.iam_summary || {}; }
  get costs()      { return this.data?.costs || {}; }
  get resourceGroups() { return this.data?.resource_groups || []; }
  get totalResources() {
    return Object.values(this.data?.summary || {}).reduce((a: any, b: any) => a + b, 0);
  }
  get topTypes() { return Object.entries(this.data?.summary || {}).slice(0, 20); }
  get maxCount() { const t = this.topTypes; return t.length ? (t[0][1] as number) : 1; }

  get sidebarStats() {
    return [
      ['Subscription', this.identity.display_name || this.identity.subscription_id],
      ['Total Resources', String(this.totalResources)],
      ['Resource Groups', String(this.resourceGroups.length)],
    ];
  }
  get overviewStats() {
    return [
      {l:'Total Resources',  v:this.totalResources, a:true},
      {l:'Resource Types',   v:this.topTypes.length},
      {l:'Resource Groups',  v:this.resourceGroups.length},
      {l:'Role Assignments', v:this.iamSum.role_assignments},
      {l:'Custom Roles',     v:this.iamSum.custom_roles},
    ];
  }
  get iamStats() {
    return [
      {l:'Role Assignments', v:this.iamSum.role_assignments},
      {l:'Role Definitions', v:this.iamSum.role_definitions},
      {l:'Custom Roles',     v:this.iamSum.custom_roles},
    ];
  }

  get allResources(): any[] {
    const flat: any[] = [];
    const subMap = this.data?.resources || {};
    for (const [sub, typeMap] of Object.entries(subMap)) {
      for (const [rtype, items] of Object.entries(typeMap as any)) {
        if (rtype.startsWith('_')) continue;
        for (const item of (items as any[])) {
          flat.push({ ...item, resourceType: rtype });
        }
      }
    }
    return flat;
  }
  get allTypes()   { return [...new Set(this.allResources.map(r => r.resourceType))].sort(); }
  get allRegions() { return [...new Set(this.allResources.map(r => r.region))].sort(); }
  get filtered() {
    const q = this.search.toLowerCase();
    return this.allResources.filter(r =>
      (!q || [r.resourceName, r.resourceType, r.region, r.resourceGroup].some((v: any) => v?.toLowerCase().includes(q)))
      && (!this.selType   || r.resourceType === this.selType)
      && (!this.selRegion || r.region       === this.selRegion)
    );
  }
  get pagedResources() { return this.filtered.slice(this.explorerPage * this.PAGE_SIZE, (this.explorerPage + 1) * this.PAGE_SIZE); }
  get totalPages()     { return Math.ceil(this.filtered.length / this.PAGE_SIZE); }
  prevPage()  { if (this.explorerPage > 0) this.explorerPage--; }
  nextPage()  { if (this.explorerPage < this.totalPages - 1) this.explorerPage++; }
  resetPage() { this.explorerPage = 0; }

  get costsByService() { return Object.entries(this.costs.by_service || {}).sort((a: any, b: any) => b[1] - a[1]); }
  get costsByRegion()  { return Object.entries(this.costs.by_region  || {}).sort((a: any, b: any) => b[1] - a[1]); }
  get maxServiceCost() { const e = this.costsByService; return e.length ? (e[0][1] as number) : 1; }

  getNumericValue(val: any): number {
    return typeof val === 'number' ? val : 0;
  }
}
