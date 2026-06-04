import { Component, Input } from '@angular/core';
@Component({
  selector: 'app-score-ring',
  standalone: true,
  template: `
    <div style="display:flex;flex-direction:column;align-items:center;gap:6px">
      <svg [attr.width]="size" [attr.height]="size" [attr.viewBox]="'0 0 '+size+' '+size">
        <circle [attr.cx]="size/2" [attr.cy]="size/2" [attr.r]="r" fill="none" stroke="var(--surface-3)" stroke-width="6"/>
        <circle [attr.cx]="size/2" [attr.cy]="size/2" [attr.r]="r" fill="none" [attr.stroke]="color" stroke-width="6"
          [attr.stroke-dasharray]="dash+' '+circ" stroke-linecap="round"
          [attr.transform]="'rotate(-90 '+(size/2)+' '+(size/2)+')'"/>
        <text [attr.x]="size/2" [attr.y]="size/2+1" text-anchor="middle" dominant-baseline="middle"
          [attr.fill]="color" [attr.font-size]="size<70?12:15" font-weight="700" font-family="IBM Plex Mono,monospace">
          {{score}}%
        </text>
      </svg>
      <span *ngIf="label" style="font-size:11px;color:var(--text-2);text-align:center">{{label}}</span>
    </div>
  `,
  imports: [import('@angular/common').then(m=>m.CommonModule)]
})
export class ScoreRingComponent {
  @Input() score: number = 0;
  @Input() size: number = 80;
  @Input() label: string = '';
  get r() { return this.size/2 - 8; }
  get circ() { return 2 * Math.PI * this.r; }
  get dash() { return (this.score/100) * this.circ; }
  get color() { return this.score>=80?'var(--green)':this.score>=60?'var(--yellow)':'var(--red)'; }
}
