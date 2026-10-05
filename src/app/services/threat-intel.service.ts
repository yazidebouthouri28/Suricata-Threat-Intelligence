import { Injectable, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom, of } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { ThreatIntelEntry } from '../models/threat-intel.model';

@Injectable({
  providedIn: 'root'
})
export class ThreatIntelService {
  private cache = new Map<string, ThreatIntelEntry>();
  readonly isLoaded = signal(false);

  constructor(private http: HttpClient) {}

  async loadThreatIntel(): Promise<void> {
    try {
      const data = await firstValueFrom(
        this.http.get<ThreatIntelEntry[]>('assets/threat_intel.json').pipe(
          catchError(() => of([])) // Handle case where file doesn't exist
        )
      );

      this.cache.clear();
      if (data && Array.isArray(data)) {
        for (const entry of data) {
          this.cache.set(entry.indicator, entry);
        }
      }
      this.isLoaded.set(true);
    } catch (err) {
      console.error('Failed to load threat intel data', err);
      this.isLoaded.set(true); // Consider loaded even if failed so UI doesn't hang
    }
  }

  lookup(indicator: string): ThreatIntelEntry | undefined {
    return this.cache.get(indicator);
  }

  getAllEntries(): ThreatIntelEntry[] {
    return [...this.cache.values()];
  }

  getByType(type: ThreatIntelEntry['type']): ThreatIntelEntry[] {
    return this.getAllEntries().filter((entry) => entry.type === type);
  }
}
