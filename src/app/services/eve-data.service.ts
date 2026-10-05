import { Injectable, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

import {
  AlertRow,
  CountEntry,
  DashboardStats,
  EveEvent,
  SEVERITY_LABELS,
} from '../models/eve.models';
import { mapAlertToDisplayCategory } from '../utils/alert-category.mapper';

const EMPTY_STATS: DashboardStats = {
  totalEvents: 0,
  alertCount: 0,
  flowCount: 0,
  firstTimestamp: null,
  lastTimestamp: null,
  eventTypes: [],
  alertCategories: [],
  alertSeverities: [],
  protocols: [],
  topSignatures: [],
  topSourceIps: [],
  topDestIps: [],
  alertsTimeline: [],
  recentAlerts: [],
};

@Injectable({ providedIn: 'root' })
export class EveDataService {
  readonly stats = signal<DashboardStats>(EMPTY_STATS);
  readonly loading = signal(false);
  readonly progress = signal(0);
  readonly error = signal<string | null>(null);

  private loadPromise: Promise<void> | null = null;
  private allAlerts: AlertRow[] = [];

  constructor(private readonly http: HttpClient) {}

  loadDashboardData(): Promise<void> {
    if (this.loadPromise) {
      return this.loadPromise;
    }

    this.loadPromise = this.fetchAndAggregate();
    return this.loadPromise;
  }

  private async fetchAndAggregate(): Promise<void> {
    this.loading.set(true);
    this.progress.set(0);
    this.error.set(null);

    try {
      const raw = await firstValueFrom(
        this.http.get('assets/eve_complet.json', { responseType: 'text' }),
      );
      const stats = this.aggregate(raw);
      this.stats.set(stats);
      this.progress.set(100);
    } catch (err) {
      this.error.set('Unable to load eve_complet.json.');
      console.error(err);
    } finally {
      this.loading.set(false);
    }
  }

  private aggregate(raw: string): DashboardStats {
    const lines = raw.split('\n');
    const eventTypes = new Map<string, number>();
    const alertCategories = new Map<string, number>();
    const alertSeverities = new Map<string, number>();
    const protocols = new Map<string, number>();
    const topSignatures = new Map<string, number>();
    const topSourceIps = new Map<string, number>();
    const topDestIps = new Map<string, number>();
    const alertsTimeline = new Map<string, number>();
    const recentAlerts: AlertRow[] = [];

    let alertCount = 0;
    let flowCount = 0;
    let firstTimestamp: string | null = null;
    let lastTimestamp: string | null = null;
    let totalEvents = 0;

    for (let index = 0; index < lines.length; index++) {
      const line = lines[index].trim();
      if (!line) {
        continue;
      }

      let event: EveEvent;
      try {
        event = JSON.parse(line) as EveEvent;
      } catch {
        continue;
      }

      totalEvents++;
      if (event.timestamp) {
        if (!firstTimestamp) {
          firstTimestamp = event.timestamp;
        }
        lastTimestamp = event.timestamp;
      }

      const eventType = event.event_type ?? 'unknown';
      eventTypes.set(eventType, (eventTypes.get(eventType) ?? 0) + 1);

      if (eventType === 'alert') {
        alertCount++;
        const rawCategory = event.alert?.category ?? 'Unknown';
        const signature = event.alert?.signature ?? 'Unknown signature';
        const category = mapAlertToDisplayCategory(rawCategory, signature);
        alertCategories.set(category, (alertCategories.get(category) ?? 0) + 1);

        const severity = event.alert?.severity ?? 0;
        const severityLabel = SEVERITY_LABELS[severity] ?? `Level ${severity}`;
        alertSeverities.set(
          severityLabel,
          (alertSeverities.get(severityLabel) ?? 0) + 1,
        );

        topSignatures.set(signature, (topSignatures.get(signature) ?? 0) + 1);

        if (event.src_ip) {
          topSourceIps.set(event.src_ip, (topSourceIps.get(event.src_ip) ?? 0) + 1);
        }
        if (event.dest_ip) {
          topDestIps.set(event.dest_ip, (topDestIps.get(event.dest_ip) ?? 0) + 1);
        }

        if (event.timestamp) {
          const day = event.timestamp.slice(0, 10);
          alertsTimeline.set(day, (alertsTimeline.get(day) ?? 0) + 1);
        }

        recentAlerts.push({
          timestamp: event.timestamp ?? '',
          signature,
          category,
          severity,
          srcIp: event.src_ip ?? '-',
          destIp: event.dest_ip ?? '-',
          action: event.alert?.action ?? '-',
        });
      }

      if (eventType === 'flow') {
        flowCount++;
        const protocol = event.proto ?? 'Unknown';
        protocols.set(protocol, (protocols.get(protocol) ?? 0) + 1);
      }

      if (index % 5000 === 0) {
        this.progress.set(Math.round((index / lines.length) * 100));
      }
    }

    recentAlerts.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
    this.allAlerts = recentAlerts;

    return {
      totalEvents,
      alertCount,
      flowCount,
      firstTimestamp,
      lastTimestamp,
      eventTypes: this.toSortedEntries(eventTypes, 12),
      alertCategories: this.toSortedEntries(alertCategories, 8),
      alertSeverities: this.toSortedEntries(alertSeverities, 5),
      protocols: this.toSortedEntries(protocols, 8),
      topSignatures: this.toSortedEntries(topSignatures, 8),
      topSourceIps: this.toSortedEntries(topSourceIps, 5),
      topDestIps: this.toSortedEntries(topDestIps, 5),
      alertsTimeline: this.toSortedEntries(alertsTimeline, 30, true),
      recentAlerts: recentAlerts.slice(0, 15),
    };
  }

  private toSortedEntries(
    map: Map<string, number>,
    limit: number,
    chronological = false,
  ): CountEntry[] {
    const entries = [...map.entries()].map(([label, count]) => ({ label, count }));

    if (chronological) {
      return entries.sort((a, b) => a.label.localeCompare(b.label)).slice(0, limit);
    }

    return entries.sort((a, b) => b.count - a.count).slice(0, limit);
  }

  getAlertsForIndicator(indicator: string): AlertRow[] {
    const value = indicator.trim().toLowerCase();
    return this.allAlerts.filter(
      (alert) =>
        alert.srcIp.toLowerCase() === value || alert.destIp.toLowerCase() === value,
    );
  }

  getObservedIps(): string[] {
    const ips = new Set<string>();
    for (const alert of this.allAlerts) {
      if (alert.srcIp !== '-') {
        ips.add(alert.srcIp);
      }
      if (alert.destIp !== '-') {
        ips.add(alert.destIp);
      }
    }
    return [...ips].sort();
  }
}
