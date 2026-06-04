import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-wellarch',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './wellarch.component.html',
})
export class WellarchComponent {
  @Input() data: any;
  @Input() meta: any;
  pillarOrder = ['ops','security','reliability','performance','cost','sustainability'];
  pillarIcons: any = {ops:'⚙',security:'🛡',reliability:'↺',performance:'⚡',cost:'◇',sustainability:'♻'};
  expanded: any = {};
  toggle(k: string) { this.expanded[k] = !this.expanded[k]; }
  colorMap: any = {green:'var(--green)',yellow:'var(--yellow)',orange:'var(--orange)',red:'var(--red)'};
  color(p: any) { return this.colorMap[p?.color]||'var(--text-2)'; }
  get overallColor() { return this.colorMap[this.data?.overall_color]||'var(--text-2)'; }
  get circumference() { return 2*Math.PI*42; }
  get dashArray() { return ((this.data?.overall_score||0)/100)*this.circumference; }
  riskBadge(r: string) { return r==='LOW'?'badge-green':r==='MEDIUM'?'badge-yellow':r==='HIGH'?'badge-orange':'badge-red'; }
  badgeClass(sev: string) { return sev==='CRITICAL'?'badge-red':sev==='HIGH'?'badge-orange':sev==='MEDIUM'?'badge-yellow':'badge-neutral'; }
}
