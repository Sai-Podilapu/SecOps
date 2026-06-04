import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-discovery',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './discovery.component.html',
})
export class DiscoveryComponent {
  @Input() data: any;
  @Input() meta: any;
  activeTab = 'overview';

  get total() { return Object.values(this.data?.summary || {}).reduce((a: any, b: any) => a + b, 0); }
  get recording() { return Object.values(this.data?.config_status || {}).filter((s: any) => s.recording).length; }
  get topTypes() { return Object.entries(this.data?.summary || {}).slice(0, 20); }
  get maxCount() { const t = this.topTypes; return t.length ? (t[0][1] as number) : 1; }
  get iamSum() { return this.data?.iam_summary || {}; }

  search = ''; selType = ''; selRegion = '';
  get allResources(): any[] {
    const flat: any[] = [];
    for (const [region, typeMap] of Object.entries(this.data?.resources || {}))
      for (const [rtype, items] of Object.entries(typeMap as any))
        for (const item of (items as any[])) flat.push({ ...item, resourceType: rtype, region: item.region || region });
    return flat;
  }
  get allTypes() { return [...new Set(this.allResources.map(r => r.resourceType))].sort(); }
  get allRegions() { return [...new Set(this.allResources.map(r => r.region))].sort(); }
  get filtered() {
    const q = this.search.toLowerCase();
    return this.allResources.filter(r =>
      (!q || [r.resourceId, r.resourceName, r.resourceType, r.region].some((v: any) => v?.toLowerCase().includes(q)))
      && (!this.selType || r.resourceType === this.selType)
      && (!this.selRegion || r.region === this.selRegion)
    );
  }

  activeRegion = '';
  activeType = '';
  explorerPage = 0;
  readonly PAGE_SIZE = 50;
  get regions() { return this.data?.regions || []; }
  regionData(r: string) { return this.data?.resources?.[r] || {}; }
  regionCount(r: string): number { 
    const values = Object.values(this.data?.resource_counts?.[r] || {}) as any[];
    return values.reduce((a: number, b: any) => a + (typeof b === 'number' ? b : 0), 0);
  }
  configStatus(r: string) { return this.data?.config_status?.[r] || {}; }

  get pagedResources() { return this.filtered.slice(this.explorerPage * this.PAGE_SIZE, (this.explorerPage + 1) * this.PAGE_SIZE); }
  get totalPages() { return Math.ceil(this.filtered.length / this.PAGE_SIZE); }
  prevPage() { if (this.explorerPage > 0) this.explorerPage--; }
  nextPage() { if (this.explorerPage < this.totalPages - 1) this.explorerPage++; }
  resetPage() { this.explorerPage = 0; }

  get costs() { return this.data?.costs || {}; }
  get costsByService() { return Object.entries(this.costs.by_service || {}).sort((a: any, b: any) => b[1] - a[1]); }
  get costsByRegion() { return Object.entries(this.costs.by_region || {}).sort((a: any, b: any) => b[1] - a[1]); }
  get maxServiceCost() { const e = this.costsByService; return e.length ? (e[0][1] as number) : 1; }

  getArrayLength(arr: any): number {
    return Array.isArray(arr) ? arr.length : 0;
  }

  getNumericValue(val: any): number {
    return typeof val === 'number' ? val : 0;
  }

  get regionBreakdown() {
    return this.regions.map((r: string) => {
      const typeMap = this.regionData(r);
      const types = Object.entries(typeMap).sort((a: any, b: any) => this.getArrayLength(b[1]) - this.getArrayLength(a[1]));
      return { region: r, count: this.regionCount(r), status: this.configStatus(r), types };
    }).filter((r: any) => r.count > 0);
  }
}
