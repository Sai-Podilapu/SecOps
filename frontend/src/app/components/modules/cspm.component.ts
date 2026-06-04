import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-cspm',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './cspm.component.html',
})
export class CspmComponent {
  @Input() data: any;
  @Input() meta: any;
  activeTab = 'overview';
  modOrder = ['compute','container','database','network','secrets','waf','cis'];
  modIcons: any = {compute:'⚙',container:'◻',database:'◈',network:'⬡',secrets:'🔑',waf:'🛡',cis:'📋'};
  expanded: any = {};

  toggleExpand(k: string) { this.expanded[k] = !this.expanded[k]; }

  scoreColor(s: any) { return s>=80?'var(--green)':s>=60?'var(--yellow)':s>=40?'var(--orange)':'var(--red)'; }
  badgeClass(sev: string) { return sev==='CRITICAL'?'badge-red':sev==='HIGH'?'badge-orange':sev==='MEDIUM'?'badge-yellow':'badge-neutral'; }

  get tabs() {
    const t = [{id:'overview',label:'Overview',score:null},{id:'failures',label:'Failures ('+( this.data?.top_failures?.length||0)+')',score:null}];
    for(const k of this.modOrder) if(this.data?.modules?.[k]) t.push({id:k,label:this.data.modules[k].label,score:this.data.modules[k].score});
    return t;
  }

  get overallColor() { const s=this.data?.overall_score||0; return this.scoreColor(s); }
  get circumference() { return 2 * Math.PI * 42; }
  get dashArray() { return ((this.data?.overall_score||0)/100)*this.circumference; }
}
