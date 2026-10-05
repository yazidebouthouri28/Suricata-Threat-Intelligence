import { DatePipe } from '@angular/common';
import { Component, effect, inject, input, output, signal } from '@angular/core';

import { ExplainKind, ExplainRequest } from '../../models/agent.model';
import { AgentService } from '../../services/agent.service';

@Component({
  selector: 'app-ai-explain-popup',
  imports: [DatePipe],
  templateUrl: './ai-explain-popup.html',
  styleUrl: './ai-explain-popup.scss',
})
export class AiExplainPopup {
  private readonly agent = inject(AgentService);

  readonly term = input.required<string>();
  readonly kind = input.required<ExplainKind>();
  readonly context = input<Record<string, unknown>>({});
  readonly closed = output<void>();

  readonly explanation = this.agent.lastExplanation;
  readonly loading = this.agent.explaining;
  readonly error = this.agent.explainError;

  private readonly requestKey = signal('');

  constructor() {
    effect(() => {
      const key = `${this.kind()}::${this.term()}::${JSON.stringify(this.context())}`;
      if (key !== this.requestKey()) {
        this.requestKey.set(key);
        void this.fetchExplanation();
      }
    });
  }

  close(): void {
    this.closed.emit();
  }

  onBackdropClick(event: MouseEvent): void {
    if (event.target === event.currentTarget) {
      this.close();
    }
  }

  private async fetchExplanation(): Promise<void> {
    const term = this.term().trim();
    if (!term) {
      return;
    }

    const request: ExplainRequest = {
      term,
      kind: this.kind(),
      context: this.context(),
    };

    await this.agent.explain(request);
  }
}
