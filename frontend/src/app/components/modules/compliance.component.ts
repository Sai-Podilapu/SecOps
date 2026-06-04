import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-compliance',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './compliance.component.html',
})
export class ComplianceComponent {
  @Input() data: any;
  @Input() meta: any;
  activeTab = 'overview';

  scoreColor(s: any) { return s==null?'var(--text-3)':s>=80?'var(--green)':s>=60?'var(--yellow)':'var(--red)'; }
  badgeType(s: any)  { return s==null?'neutral':s>=80?'green':s>=60?'yellow':'red'; }

  sections = [
    {label:'Config Rules', key:'config_rules'},
    {label:'Security Hub', key:'security_hub'},
    {label:'IAM',          key:'iam_compliance'},
    {label:'CloudTrail',   key:'cloudtrail'},
    {label:'GuardDuty',    key:'guardduty'},
  ];
  nav = [
    {id:'overview', label:'Overview',      icon:'◈'},
    {id:'config',   label:'Config Rules',  icon:'◉'},
    {id:'hub',      label:'Security Hub',  icon:'⬡'},
    {id:'iam',      label:'IAM Compliance',icon:'◎'},
    {id:'trail',    label:'CloudTrail',    icon:'◇'},
    {id:'guardduty',label:'GuardDuty',     icon:'◆'},
  ];

  /** Map tab id → data key for score lookup */
  private readonly tabKeyMap: Record<string, string> = {
    config:   'config_rules',
    hub:      'security_hub',
    iam:      'iam_compliance',
    trail:    'cloudtrail',
    guardduty:'guardduty',
  };

  tabScore(tabId: string): number | null {
    const key = this.tabKeyMap[tabId];
    if (!key) return null;
    const score = this.data?.[key]?.score;
    return score != null ? score : null;
  }

  checkStatusClass(s: string) {
    const u = (s || '').toUpperCase();
    return u==='PASS'||u==='COMPLIANT' ? 'badge-green' : u==='FAIL'||u==='NON_COMPLIANT' ? 'badge-red' : 'badge-neutral';
  }
}
