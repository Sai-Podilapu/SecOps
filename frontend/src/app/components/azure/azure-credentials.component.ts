import { Component, Input, Output, EventEmitter, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

const AZURE_REGIONS = [
  'eastus','eastus2','westus','westus2','westus3','centralus','northcentralus','southcentralus',
  'westcentralus','canadacentral','canadaeast','brazilsouth',
  'northeurope','westeurope','uksouth','ukwest','francecentral','germanywestcentral',
  'switzerlandnorth','norwayeast','swedencentral',
  'eastasia','southeastasia','japaneast','japanwest','australiaeast','australiasoutheast',
  'centralindia','southindia','westindia','koreacentral','uaenorth','southafricanorth',
];

@Component({
  selector: 'app-azure-credentials',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
<div style="width:100%;max-width:520px;animation:fadeIn 0.4s ease">
  <div style="margin-bottom:24px;text-align:center">
    <div style="width:52px;height:52px;border-radius:14px;background:linear-gradient(135deg,#0078d4,#005a9e);display:flex;align-items:center;justify-content:center;margin:0 auto 14px;box-shadow:0 8px 20px -8px #0078d480">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none"><path d="M11.5 2L4 8.5V21h6v-7h3v7h6V8.5L11.5 2z" fill="white" opacity="0.9"/></svg>
    </div>
    <h1 style="font-size:20px;font-weight:700;letter-spacing:-0.03em;margin-bottom:6px">Azure Credentials</h1>
    <p style="color:var(--text-2);font-size:13px">Service Principal (App Registration) · read-only</p>
  </div>

  <div *ngIf="error" style="background:var(--red-dim);border:1px solid var(--red-b);border-radius:var(--radius);padding:10px 14px;margin-bottom:16px;font-size:12px;color:var(--red);display:flex;gap:8px">
    <span>⚠</span><span>{{error}}</span>
  </div>

  <div class="card" style="overflow:hidden">
    <!-- Tenant ID -->
    <div style="padding:12px 16px">
      <div style="font-size:10px;font-weight:600;color:var(--text-3);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.07em">Tenant ID</div>
      <input autofocus autocomplete="off" type="text" [(ngModel)]="tenantId"
        placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        style="background:none;border:none;outline:none;font-family:var(--font-mono);font-size:12px;color:var(--text-1);width:100%"/>
    </div>
    <div style="height:1px;background:var(--border)"></div>
    <!-- Client ID -->
    <div style="padding:12px 16px">
      <div style="font-size:10px;font-weight:600;color:var(--text-3);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.07em">Client ID <span style="font-weight:400;opacity:0.6">(App ID)</span></div>
      <input autocomplete="off" type="text" [(ngModel)]="clientId"
        placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        style="background:none;border:none;outline:none;font-family:var(--font-mono);font-size:12px;color:var(--text-1);width:100%"/>
    </div>
    <div style="height:1px;background:var(--border)"></div>
    <!-- Client Secret -->
    <div style="padding:12px 16px">
      <div style="font-size:10px;font-weight:600;color:var(--text-3);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.07em">Client Secret</div>
      <div style="display:flex;align-items:center;gap:8px">
        <input autocomplete="off" [type]="showSecret?'text':'password'" [(ngModel)]="clientSecret"
          placeholder="••••••••••••••••••••••••••••••••"
          style="background:none;border:none;outline:none;font-family:var(--font-mono);font-size:12px;color:var(--text-1);flex:1"/>
        <button (click)="showSecret=!showSecret" style="background:none;border:none;cursor:pointer;color:var(--text-3);font-size:11px;flex-shrink:0">
          {{showSecret?'hide':'show'}}
        </button>
      </div>
    </div>
    <div style="height:1px;background:var(--border)"></div>
    <!-- Subscription ID -->
    <div style="padding:12px 16px">
      <div style="font-size:10px;font-weight:600;color:var(--text-3);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.07em">Subscription ID <span style="font-weight:400;opacity:0.6">(Optional — auto-detect)</span></div>
      <input autocomplete="off" type="text" [(ngModel)]="subscriptionId"
        placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (leave blank to auto-detect)"
        style="background:none;border:none;outline:none;font-family:var(--font-mono);font-size:12px;color:var(--text-1);width:100%"/>
    </div>
  </div>

  <button [disabled]="!valid" (click)="submit()"
    [style.background]="valid?'linear-gradient(135deg,#0078d4,#005a9e)':'var(--surface-2)'"
    [style.color]="valid?'#fff':'var(--text-3)'"
    [style.box-shadow]="valid?'0 0 16px #0078d430':'none'"
    style="width:100%;margin-top:14px;padding:11px 0;border:none;border-radius:var(--radius);font-size:13px;font-weight:600;cursor:pointer;transition:all 0.15s">
    Start Azure Scan →
  </button>

  <div style="display:flex;gap:16px;margin-top:14px;justify-content:center">
    <span *ngFor="let t of ['Read-only Reader role','Not stored','TLS encrypted']"
      style="font-size:11px;color:var(--text-3);display:flex;align-items:center;gap:4px">
      <span style="color:var(--green)">✓</span>{{t}}
    </span>
  </div>

  <div style="margin-top:20px;padding:14px 16px;background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius);font-size:11px;color:var(--text-3)">
    <div style="font-weight:700;color:var(--text-2);margin-bottom:6px">🔑 Required Azure Roles</div>
    <div>Assign <strong style="color:var(--text-1)">Reader</strong> + <strong style="color:var(--text-1)">Security Reader</strong> on the subscription scope to your App Registration.</div>
  </div>
</div>
  `,
})
export class AzureCredentialsComponent implements OnInit {
  @Input() activeModule = 'discovery';
  @Input() error = '';
  @Input() savedCreds: any = null;
  @Output() scan = new EventEmitter<any>();

  tenantId       = '';
  clientId       = '';
  clientSecret   = '';
  subscriptionId = '';
  showSecret     = false;

  ngOnInit() {
    if (this.savedCreds) {
      this.tenantId       = this.savedCreds.tenantId       || '';
      this.clientId       = this.savedCreds.clientId       || '';
      this.clientSecret   = this.savedCreds.clientSecret   || '';
      this.subscriptionId = this.savedCreds.subscriptionId || '';
    }
  }

  get valid() {
    return this.tenantId.trim() && this.clientId.trim() && this.clientSecret.trim();
  }

  submit() {
    if (!this.valid) return;
    this.scan.emit({
      tenantId:       this.tenantId.trim(),
      clientId:       this.clientId.trim(),
      clientSecret:   this.clientSecret.trim(),
      subscriptionId: this.subscriptionId.trim(),
    });
  }
}
