import { DecimalPipe, NgClass } from '@angular/common';
import { Component, computed, inject, OnInit, signal } from '@angular/core';
import { ChartConfiguration, ChartData } from 'chart.js';
import { BaseChartDirective } from 'ng2-charts';

import { AiExplainPopup } from '../components/ai-explain-popup/ai-explain-popup';
import { AskAgent } from '../components/ask-agent/ask-agent';
import { ExplainKind, IndicatorType } from '../models/agent.model';
import { SEVERITY_LABELS } from '../models/eve.models';
import { EveDataService } from '../services/eve-data.service';
import { ThreatIntelService } from '../services/threat-intel.service';
import { ThreatIntelEntry } from '../models/threat-intel.model';

@Component({
  selector: 'app-dashboard',
  imports: [BaseChartDirective, DecimalPipe, NgClass, AskAgent, AiExplainPopup],
  templateUrl: './dashboard.html',
  styleUrl: './dashboard.scss',
})export class Dashboard implements OnInit {
  private readonly eveData = inject(EveDataService);
  private readonly threatIntel = inject(ThreatIntelService);

  readonly stats = this.eveData.stats;
  readonly loading = this.eveData.loading;
  readonly progress = this.eveData.progress;
  readonly error = this.eveData.error;
  readonly severityLabels = SEVERITY_LABELS;

  readonly agentOpen = signal(false);
  readonly agentIndicator = signal('');
  readonly agentType = signal<IndicatorType>('ip');

  readonly explainOpen = signal(false);
  readonly explainTerm = signal('');
  readonly explainKind = signal<ExplainKind>('general');
  readonly explainContext = signal<Record<string, unknown>>({});
  readonly summaryCards = computed(() => {
    const data = this.stats();
    return [
      { label: 'Total events', value: data.totalEvents, accent: '#38bdf8' },
      { label: 'Alerts', value: data.alertCount, accent: '#f87171' },
      { label: 'Flows', value: data.flowCount, accent: '#34d399' },
      { label: 'Event types', value: data.eventTypes.length, accent: '#a78bfa' },
    ];
  });

  readonly eventTypeChart = computed<ChartData<'doughnut'>>(() => {
    const data = this.stats().eventTypes;
    return {
      labels: data.map((entry) => entry.label),
      datasets: [
        {
          data: data.map((entry) => entry.count),
          backgroundColor: [
            '#38bdf8',
            '#34d399',
            '#f87171',
            '#fbbf24',
            '#a78bfa',
            '#fb7185',
            '#22d3ee',
            '#4ade80',
            '#818cf8',
            '#f472b6',
            '#94a3b8',
            '#cbd5e1',
          ],
          borderWidth: 0,
        },
      ],
    };
  });

  readonly alertsTimelineChart = computed<ChartData<'line'>>(() => {
    const data = this.stats().alertsTimeline;
    return {
      labels: data.map((entry) => entry.label),
      datasets: [
        {
          label: 'Alerts',
          data: data.map((entry) => entry.count),
          borderColor: '#f87171',
          backgroundColor: 'rgba(248, 113, 113, 0.15)',
          fill: true,
          tension: 0.3,
          pointRadius: 3,
        },
      ],
    };
  });

  readonly categoryChart = computed<ChartData<'bar'>>(() =>
    this.buildBarChart(this.stats().alertCategories, '#38bdf8'),
  );

  readonly severityChart = computed<ChartData<'bar'>>(() =>
    this.buildBarChart(this.stats().alertSeverities, '#fbbf24'),
  );

  readonly protocolChart = computed<ChartData<'bar'>>(() =>
    this.buildBarChart(this.stats().protocols, '#34d399'),
  );

  readonly doughnutOptions: ChartConfiguration<'doughnut'>['options'] = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom',
        labels: { color: '#cbd5e1', boxWidth: 12 },
      },
    },
  };

  readonly lineOptions: ChartConfiguration<'line'>['options'] = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      x: {
        ticks: { color: '#94a3b8', maxRotation: 45 },
        grid: { color: 'rgba(148, 163, 184, 0.12)' },
      },
      y: {
        beginAtZero: true,
        ticks: { color: '#94a3b8', precision: 0 },
        grid: { color: 'rgba(148, 163, 184, 0.12)' },
      },
    },
    plugins: {
      legend: { display: false },
    },
  };

  readonly barOptions: ChartConfiguration<'bar'>['options'] = {
    responsive: true,
    maintainAspectRatio: false,
    indexAxis: 'y',
    scales: {
      x: {
        beginAtZero: true,
        ticks: { color: '#94a3b8', precision: 0 },
        grid: { color: 'rgba(148, 163, 184, 0.12)' },
      },
      y: {
        ticks: { color: '#cbd5e1' },
        grid: { display: false },
      },
    },
    plugins: {
      legend: { display: false },
    },
  };

  ngOnInit(): void {
    void this.eveData.loadDashboardData();
    void this.threatIntel.loadThreatIntel();
  }

  formatTimestamp(value: string | null): string {
    if (!value) {
      return '-';
    }

    const parsed = new Date(value.replace(/\+(\d{2})(\d{2})$/, '+$1:$2'));
    return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
  }

  severityLabel(severity: number): string {
    return SEVERITY_LABELS[severity] ?? `Level ${severity}`;
  }

  private buildBarChart(
    entries: { label: string; count: number }[],
    color: string,
  ): ChartData<'bar'> {
    return {
      labels: entries.map((entry) => entry.label),
      datasets: [
        {
          data: entries.map((entry) => entry.count),
          backgroundColor: color,
          borderRadius: 6,
          barThickness: 18,
        },
      ],
    };
  }

  getThreatIntel(indicator: string): ThreatIntelEntry | undefined {
    return this.threatIntel.lookup(indicator);
  }


  getThreatTooltip(entry: ThreatIntelEntry | undefined): string {
    if (!entry) return '';
    const score = entry.confidence_score;
    const cats = entry.threat_categories?.join(', ') || 'Aucune catégorie';
    return `Score API: ${score}% | Catégories: ${cats} | Source: ${entry.threat_source}`;
  }

  getThreatScore10(entry: ThreatIntelEntry | undefined): string {
    if (!entry) return '-/10';
    const outOf10 = 10 - Math.round(entry.confidence_score / 10);
    return `${outOf10}/10`;
  }

  getThreatBadgeClass(entry: ThreatIntelEntry | undefined): string {
    if (!entry) return 'badge-unknown';
    return entry.malicious ? 'badge-malicious' : 'badge-ok';
  }

  getThreatLabel(entry: ThreatIntelEntry | undefined): string {
    const scoreText = this.getThreatScore10(entry);
    if (!entry) return `Non vérifié (${scoreText})`;
    return entry.malicious ? `⚠️ Malveillant (${scoreText})` : `OK (${scoreText})`;
  }

  openAgent(indicator: string, type: IndicatorType = 'ip'): void {
    this.agentIndicator.set(indicator);
    this.agentType.set(type);
    this.agentOpen.set(true);
  }

  closeAgent(): void {
    this.agentOpen.set(false);
  }

  openExplain(
    term: string,
    kind: ExplainKind,
    context: Record<string, unknown> = {},
  ): void {
    this.explainTerm.set(term);
    this.explainKind.set(kind);
    this.explainContext.set(context);
    this.explainOpen.set(true);
  }

  closeExplain(): void {
    this.explainOpen.set(false);
  }

  onChartSegmentClick(
    event: { active?: object[] },
    entries: Array<{ label: string; count: number }>,
    kind: ExplainKind,
  ): void {
    const active = event.active as Array<{ index: number }> | undefined;
    const index = active?.[0]?.index;
    if (index === undefined) {
      return;
    }

    const entry = entries[index];
    if (!entry) {
      return;
    }

    this.openExplain(entry.label, kind, {
      count: entry.count,
      chartSection: kind,
    });
  }

  explainThreatIntel(indicator: string, entry: ThreatIntelEntry | undefined): void {
    if (!entry) {
      this.openExplain(indicator, 'threat_intel', {
        status: 'not_enriched',
        message: 'No threat intelligence entry found for this indicator.',
      });
      return;
    }

    this.openExplain(indicator, 'threat_intel', {
      malicious: entry.malicious,
      confidenceScore: entry.confidence_score,
      threatCategories: entry.threat_categories,
      threatSource: entry.threat_source,
      indicatorType: entry.type,
    });
  }
}