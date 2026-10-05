import { DatePipe } from '@angular/common';
import { Component, computed, inject, input, output, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';

import { IndicatorType } from '../../models/agent.model';
import { AgentService } from '../../services/agent.service';
import { EveDataService } from '../../services/eve-data.service';
import { ThreatIntelService } from '../../services/threat-intel.service';

@Component({
  selector: 'app-ask-agent',
  imports: [FormsModule, DatePipe],
  templateUrl: './ask-agent.html',
  styleUrl: './ask-agent.scss',
})
export class AskAgent {
  private readonly agent = inject(AgentService);
  private readonly eveData = inject(EveDataService);
  private readonly threatIntel = inject(ThreatIntelService);

  readonly initialIndicator = input<string>('');
  readonly initialType = input<IndicatorType>('ip');
  readonly closed = output<void>();

  readonly indicatorType = signal<IndicatorType>('ip');
  readonly indicatorValue = signal('');
  readonly health = signal<{ llmConfigured: boolean; knowledgeDocuments: number } | null>(
    null,
  );

  readonly analyzing = this.agent.analyzing;
  readonly result = this.agent.lastResult;
  readonly error = this.agent.error;

  readonly indicatorOptions = computed(() => {
    const type = this.indicatorType();
    if (type === 'ip') {
      return this.eveData.getObservedIps();
    }
    if (type === 'domain') {
      return this.threatIntel.getByType('domain').map((entry) => entry.indicator);
    }
    return [];
  });

  ngOnInit(): void {
    this.indicatorType.set(this.initialType());
    this.indicatorValue.set(this.initialIndicator());
    void this.agent.checkHealth().then((health) => {
      if (health) {
        this.health.set({
          llmConfigured: health.llmConfigured,
          knowledgeDocuments: health.knowledgeDocuments,
        });
      }
    });
  }

  onTypeChange(type: IndicatorType): void {
    this.indicatorType.set(type);
    const options = this.indicatorOptions();
    if (options.length && !options.includes(this.indicatorValue())) {
      this.indicatorValue.set(options[0] ?? '');
    }
  }

  selectIndicator(value: string): void {
    this.indicatorValue.set(value);
  }

  closePanel(): void {
    this.closed.emit();
  }

  async analyze(): Promise<void> {
    const indicator = this.indicatorValue().trim();
    if (!indicator) {
      return;
    }

    const type = this.indicatorType();
    const relatedAlerts =
      type === 'ip' ? this.eveData.getAlertsForIndicator(indicator) : [];
    const ti = this.threatIntel.lookup(indicator);
    const request = this.agent.buildRequest(indicator, type, relatedAlerts, ti);

    await this.agent.analyze(request);
  }
}
