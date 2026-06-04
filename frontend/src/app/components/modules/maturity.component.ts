import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-maturity',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './maturity.component.html',
})
export class MaturityComponent {
  @Input() data: any;
  @Input() meta: any;
  domainOrder = ['iam','infra','data','detection','response'];
  expanded: any = {};
  toggle(k: string) { this.expanded[k] = !this.expanded[k]; }
  colorMap: any = {green:'var(--green)',cyan:'var(--cyan)',yellow:'var(--yellow)',orange:'var(--orange)',red:'var(--red)'};
  color(d: any) { return this.colorMap[d?.color]||'var(--text-2)'; }
  levelLabels: any = {1:'Initial',2:'Developing',3:'Defined',4:'Managed',5:'Optimized'};
  get overallColor() { return this.colorMap[this.data?.overall_color]||'var(--text-2)'; }
  get circumference() { return 2*Math.PI*42; }
  get dashArray() { return ((this.data?.overall_score||0)/100)*this.circumference; }
  badgeClass(sev: string) { return sev==='CRITICAL'?'badge-red':sev==='HIGH'?'badge-orange':sev==='MEDIUM'?'badge-yellow':'badge-neutral'; }
  levels = [1,2,3,4,5];
}
