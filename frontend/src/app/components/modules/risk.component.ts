import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
@Component({
  selector: 'app-risk',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './risk.component.html',
})
export class RiskComponent {
  @Input() data: any;
  @Input() meta: any;
  activeTab = 'overview';
  nav = [
    {id:'overview',  label:'Overview',  icon:'★'},
    {id:'findings',  label:'Findings',  icon:'◈'},
    {id:'inspector', label:'Inspector', icon:'◉'},
    {id:'guardduty', label:'GuardDuty', icon:'◆'},
    {id:'macie',     label:'Macie',     icon:'◎'},
  ];
  badgeClass(sev: string) {
    const m: any = {CRITICAL:'badge-red',HIGH:'badge-orange',MEDIUM:'badge-yellow',LOW:'badge-neutral',INFORMATIONAL:'badge-neutral'};
    return 'badge ' + (m[sev] || 'badge-neutral');
  }
  sourceClass(src: string) {
    const m: any = {'Inspector':'badge-purple','Macie':'badge-cyan','Security Hub':'badge-accent','GuardDuty':'badge-orange'};
    return 'badge ' + (m[src] || 'badge-neutral');
  }
  riskColor(lvl: string) {
    return lvl==='CRITICAL'?'var(--red)':lvl==='HIGH'?'var(--orange)':lvl==='MEDIUM'?'var(--yellow)':'var(--green)';
  }
  sourceEntries(): [string, number][] {
    return Object.entries(this.data?.summary?.source_counts || {}) as [string, number][];
  }
}
