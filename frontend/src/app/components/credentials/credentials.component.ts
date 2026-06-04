import { Component, Input, Output, EventEmitter } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

const REGIONS = [
  'ap-south-1','ap-southeast-1','ap-southeast-2','ap-northeast-1','ap-northeast-2',
  'ap-northeast-3','eu-west-1','eu-west-2','eu-west-3','eu-central-1','eu-north-1',
  'us-east-1','us-east-2','us-west-1','us-west-2','ca-central-1','sa-east-1','me-south-1','af-south-1'
];

@Component({
  selector: 'app-credentials',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './credentials.component.html',
})
export class CredentialsComponent {
  @Input() activeModule: string = 'discovery';
  @Input() error: string = '';
  @Input() savedCreds: any = null;
  @Output() scan = new EventEmitter<any>();

  accessKey  = '';
  secretKey  = '';
  region     = '';
  allRegions = false;
  showSecret = false;
  regions    = REGIONS;

  ngOnInit() {
    if (this.savedCreds) {
      this.accessKey  = this.savedCreds.accessKey  || '';
      this.secretKey  = this.savedCreds.secretKey  || '';
      this.region     = this.savedCreds.region     || '';
      this.allRegions = this.savedCreds.allRegions || false;
    }
  }

  get valid()    { return this.accessKey.trim() && this.secretKey.trim(); }

  toggleAllRegions() {
    this.allRegions = !this.allRegions;
    if (this.allRegions) this.region = '';
  }

  submit() {
    if (!this.valid) return;
    this.scan.emit({
      accessKey:  this.accessKey.trim(),
      secretKey:  this.secretKey.trim(),
      region:     this.allRegions ? '' : (this.region || 'us-east-1'),
      allRegions: this.allRegions,
    });
  }
}
