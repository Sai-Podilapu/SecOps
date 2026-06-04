import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
@Component({
  selector: 'app-badge',
  standalone: true,
  imports: [CommonModule],
  template: `<span class="badge" [class]="'badge badge-'+type+(small?' badge-sm':'')">{{text}}</span>`
})
export class BadgeComponent {
  @Input() type: string = 'neutral';
  @Input() text: string = '';
  @Input() small: boolean = false;
}
