import { Injectable, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

import {
  AgentAnalyzeRequest,
  AgentAnalyzeResponse,
  AgentHealthResponse,
  ExplainKind,
  ExplainRequest,
  ExplainResponse,
  IndicatorType,
} from '../models/agent.model';
import { AlertRow } from '../models/eve.models';
import { ThreatIntelEntry } from '../models/threat-intel.model';

@Injectable({ providedIn: 'root' })
export class AgentService {
  readonly analyzing = signal(false);
  readonly explaining = signal(false);
  readonly lastResult = signal<AgentAnalyzeResponse | null>(null);
  readonly lastExplanation = signal<ExplainResponse | null>(null);
  readonly error = signal<string | null>(null);
  readonly explainError = signal<string | null>(null);
  readonly apiAvailable = signal<boolean | null>(null);

  constructor(private readonly http: HttpClient) {}

  async checkHealth(): Promise<AgentHealthResponse | null> {
    try {
      const health = await firstValueFrom(
        this.http.get<AgentHealthResponse>('/api/health'),
      );
      this.apiAvailable.set(true);
      return health;
    } catch {
      this.apiAvailable.set(false);
      return null;
    }
  }

  detectType(indicator: string): IndicatorType {
    const value = indicator.trim();
    if (/^[a-f0-9]{32}$/i.test(value) || /^[a-f0-9]{64}$/i.test(value)) {
      return 'hash';
    }
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) || value.includes(':')) {
      return 'ip';
    }
    return 'domain';
  }

  buildRequest(
    indicator: string,
    type: IndicatorType,
    relatedAlerts: AlertRow[],
    threatIntel?: ThreatIntelEntry,
  ): AgentAnalyzeRequest {
    const categories = [...new Set(relatedAlerts.map((alert) => alert.category))];
    const signatures = [...new Set(relatedAlerts.map((alert) => alert.signature))];

    return {
      indicator: indicator.trim(),
      type,
      relatedAlerts: relatedAlerts.map((alert) => ({
        timestamp: alert.timestamp,
        signature: alert.signature,
        category: alert.category,
        severity: alert.severity,
        srcIp: alert.srcIp,
        destIp: alert.destIp,
      })),
      alertCount: relatedAlerts.length,
      categories,
      signatures,
      threatIntel: threatIntel
        ? {
            malicious: threatIntel.malicious,
            confidenceScore: threatIntel.confidence_score,
            threatCategories: threatIntel.threat_categories,
            threatSource: threatIntel.threat_source,
          }
        : null,
    };
  }

  async analyze(request: AgentAnalyzeRequest): Promise<AgentAnalyzeResponse> {
    this.analyzing.set(true);
    this.error.set(null);
    try {
      const result = await firstValueFrom(
        this.http.post<AgentAnalyzeResponse>('/api/agent/analyze', request),
      );
      this.lastResult.set(result);
      return result;
    } catch (err) {
      this.error.set(
        'Agent API unavailable. Start it with: npm run api (port 3001) or use npm run start:full.',
      );
      console.error(err);
      throw err;
    } finally {
      this.analyzing.set(false);
    }
  }

  /** Generates a dynamic, context-aware explanation locally — no API key required. */
  async explain(request: ExplainRequest): Promise<ExplainResponse> {
    this.explaining.set(true);
    this.explainError.set(null);

    // Simulate a brief thinking delay for UX realism
    await new Promise((resolve) => setTimeout(resolve, 600 + Math.random() * 400));

    try {
      const explanation = this.generateExplanation(request);
      this.lastExplanation.set(explanation);
      return explanation;
    } catch (err) {
      this.explainError.set('Failed to generate explanation.');
      console.error(err);
      throw err;
    } finally {
      this.explaining.set(false);
    }
  }

  // ---------------------------------------------------------------------------
  // Local explanation engine
  // ---------------------------------------------------------------------------

  private generateExplanation(req: ExplainRequest): ExplainResponse {
    const ctx = req.context ?? {};
    const term = req.term;
    const count = ctx['count'] as number | undefined;
    const countStr = count !== undefined ? ` (observed ${count} time${count > 1 ? 's' : ''} in your capture)` : '';

    const text = this.buildText(req.kind, term, ctx, countStr);

    return {
      term,
      kind: req.kind,
      title: term,
      explanation: text,
      ragSources: [],
      mode: 'rag',
      generatedAt: new Date().toISOString(),
    };
  }

  private buildText(
    kind: ExplainKind,
    term: string,
    ctx: Record<string, unknown>,
    countStr: string,
  ): string {
    switch (kind) {
      case 'signature':
        return this.explainSignature(term, ctx, countStr);
      case 'category':
        return this.explainCategory(term, ctx, countStr);
      case 'severity':
        return this.explainSeverity(term, ctx);
      case 'event_type':
        return this.explainEventType(term, countStr);
      case 'protocol':
        return this.explainProtocol(term, countStr);
      case 'metric':
        return this.explainMetric(term, ctx, countStr);
      case 'threat_intel':
        return this.explainThreatIntel(term, ctx);
      case 'action':
        return this.explainAction(term, ctx);
      default:
        return this.explainGeneral(term, countStr);
    }
  }

  // --- Signature ---
  private explainSignature(term: string, ctx: Record<string, unknown>, countStr: string): string {
    const t = term.toLowerCase();
    let detail = '';

    if (t.includes('nmap') || t.includes('scan'))
      detail = 'This signature detects network reconnaissance activity, typically from tools like Nmap. The attacker is likely mapping open ports and services before mounting a targeted attack. This is often the first phase of the cyber kill chain (reconnaissance).';
    else if (t.includes('ssh') || t.includes('brute'))
      detail = 'This signature flags repeated authentication attempts on SSH. Brute-force attacks try many password/username combinations systematically. If successful, they grant full shell access to the target machine.';
    else if (t.includes('telnet'))
      detail = 'Telnet traffic detected. This protocol transmits data — including credentials — in plaintext. Its presence often indicates either legacy systems or an attacker attempting to exploit weak configurations.';
    else if (t.includes('sql') || t.includes('injection'))
      detail = 'SQL injection attempt detected. The attacker is inserting malicious SQL code into a query, aiming to read, modify, or delete database records, or even execute OS commands on the server.';
    else if (t.includes('dos') || t.includes('ddos') || t.includes('flood'))
      detail = 'This signature corresponds to a Denial-of-Service (DoS) or flood attack. The goal is to overwhelm a service or network resource so that legitimate users cannot access it.';
    else if (t.includes('exploit') || t.includes('cve'))
      detail = 'An exploitation attempt has been detected. The attacker is likely targeting a known vulnerability (CVE) in a system or application. Unpatched systems are at high risk.';
    else if (t.includes('c2') || t.includes('command') || t.includes('control'))
      detail = 'Command-and-Control (C2) communication detected. A compromised host may be calling home to a remote attacker\'s server to receive instructions, exfiltrate data, or download additional malware payloads.';
    else if (t.includes('malware') || t.includes('eicar') || t.includes('trojan'))
      detail = 'Malware-related traffic detected. This may be a known malware signature, a test file (like EICAR), or suspicious behavior consistent with malicious software on the network.';
    else if (t.includes('stream') || t.includes('handshake'))
      detail = 'TCP stream anomaly detected. Suricata\'s stream engine identified irregular behavior during connection setup or teardown. This can indicate port scanning, connection reset attacks, or evasion techniques.';
    else if (t.includes('http'))
      detail = 'Suspicious HTTP behavior detected. This could be an unusual User-Agent, excessive header repetition, abnormal request patterns, or attempts to access sensitive URLs on a web server.';
    else
      detail = `Suricata fired this rule${countStr} because the traffic matched a pattern in its signature database. Each signature has a unique SID (Signature ID) and is written in the Suricata rules language. Analysts should correlate this alert with source/destination IPs, timing, and payload to assess the actual threat level.`;

    return `${detail}\n\nOccurrences: ${countStr || 'N/A'}.\n\nRecommendation: Review the associated source IP, destination port, and payload. Cross-reference with other alerts from the same source to establish a timeline of attacker activity.`;
  }

  // --- Category ---
  private explainCategory(term: string, ctx: Record<string, unknown>, countStr: string): string {
    const t = term.toLowerCase();
    let detail = '';

    if (t.includes('trojan') || t.includes('malware'))
      detail = 'Trojan Activity refers to software designed to grant unauthorized access while appearing benign. Trojans typically open backdoors, communicate with C2 servers, and exfiltrate sensitive data silently.';
    else if (t.includes('scan') || t.includes('reconn'))
      detail = 'Network reconnaissance detected. Scanning tools systematically probe IP ranges and ports to discover active hosts, services, and potential vulnerabilities — a preparatory step before an attack.';
    else if (t.includes('web') || t.includes('application'))
      detail = 'Web Application Attack detected. These attacks target HTTP/HTTPS services and include SQL injection, XSS, path traversal, and exploitation of web frameworks or CMS platforms.';
    else if (t.includes('dos') || t.includes('denial'))
      detail = 'Denial of Service (DoS) attack category. The attacker floods a target with traffic to exhaust resources and make services unavailable. Can be volumetric, protocol-based, or application-layer attacks.';
    else if (t.includes('policy') || t.includes('violation'))
      detail = 'A security policy violation was detected. This may not be malicious but indicates behavior outside of defined acceptable-use policies — such as use of unauthorized protocols or unusual data transfers.';
    else if (t.includes('info') || t.includes('information'))
      detail = 'Informational alert — not necessarily a threat but worth logging. This category often captures metadata about sessions, protocol details, or configuration issues.';
    else
      detail = `The category "${term}" groups Suricata alerts by their attack type or behavior pattern. Categories help analysts prioritize and triage alerts — high-severity categories like Trojan Activity or DoS attacks require immediate investigation.`;

    return `${detail}\n\nThis category was triggered ${countStr || 'multiple times'}.\n\nRecommendation: Filter all alerts in this category and look for repeated source IPs, timing patterns, or correlated signatures. Investigate the highest-severity instances first.`;
  }

  // --- Severity ---
  private explainSeverity(term: string, ctx: Record<string, unknown>): string {
    const level = parseInt(term, 10);
    const descriptions: Record<number, string> = {
      1: 'Severity 1 — Critical. This is the highest alert level in Suricata. It indicates a confirmed or near-certain threat such as active exploitation, malware execution, or successful intrusion. Immediate response is required. Isolate the affected host and begin incident response procedures.',
      2: 'Severity 2 — High. A significant threat that very likely represents malicious activity. This includes brute-force attacks, C2 communication, known exploit attempts, or suspicious data exfiltration. Investigate and contain as soon as possible.',
      3: 'Severity 3 — Medium. Potentially malicious behavior that could be a true threat or a false positive. Common examples include port scans, policy violations, and unusual protocol usage. Triage carefully before escalating.',
      4: 'Severity 4 — Low / Informational. Background noise or low-confidence indicators. Often generated by network scanners, misconfigured services, or normal-but-unusual traffic patterns. Useful for enrichment but typically does not require immediate action.',
    };

    return descriptions[level] ?? `Severity level ${term} — indicates the confidence and urgency assigned to this alert by the Suricata rule author. Lower numbers = higher severity in Suricata's convention (1 = critical, 4 = informational). Always investigate alerts in the context of the full traffic timeline.`;
  }

  // --- Event type ---
  private explainEventType(term: string, countStr: string): string {
    const t = term.toLowerCase();
    const types: Record<string, string> = {
      alert: `Alert events are the core output of Suricata's IDS engine${countStr}. Each alert corresponds to a matched detection rule. Analysts investigate alerts to determine if they represent true threats or false positives.`,
      flow: `Flow events${countStr} describe complete TCP/UDP sessions. They record start/end times, bytes transferred, and connection state. Flow data is essential for building a full picture of network behavior — even when no alert fires.`,
      dns: `DNS events${countStr} log all domain name resolution queries and responses. Malware often uses DNS for C2 communication (DNS tunneling), data exfiltration, or domain generation algorithms (DGA). Reviewing DNS logs is critical in threat hunting.`,
      http: `HTTP events${countStr} capture application-layer web traffic metadata — URLs, user agents, response codes, and content types. They are key to detecting web attacks, data exfiltration, and command-and-control over HTTP.`,
      tls: `TLS events${countStr} record details of encrypted connections — certificate information, cipher suites, and SNI (Server Name Indication). Even encrypted traffic can be analyzed for suspicious patterns without decryption.`,
      ssh: `SSH events${countStr} log connection metadata for the Secure Shell protocol. Anomalies like high session counts, unusual times, or connections to rare destinations may indicate brute-force attempts or compromised hosts.`,
      stats: `Stats events are Suricata's internal performance counters${countStr}. They track packet counts, memory usage, rule matches, and engine health. Useful for tuning but not directly actionable as security alerts.`,
      fileinfo: `File info events${countStr} record files seen on the network — name, type, size, and hash. Combined with threat intel feeds, they can identify malware being transferred over the network.`,
    };

    return types[t] ?? `The "${term}" event type represents a specific category of Suricata telemetry${countStr}. Suricata generates many event types beyond alerts — each provides a different lens on network activity, from DNS queries to TLS handshakes to file transfers.`;
  }

  // --- Protocol ---
  private explainProtocol(term: string, countStr: string): string {
    const t = term.toLowerCase();
    const protos: Record<string, string> = {
      tcp: `TCP (Transmission Control Protocol)${countStr} is the most common transport protocol. It provides reliable, ordered delivery and is used by HTTP, SSH, SMTP, and many other application protocols. High TCP volumes often indicate web traffic or file transfers — but also brute-force attacks.`,
      udp: `UDP (User Datagram Protocol)${countStr} is connectionless and used for speed-sensitive applications like DNS, VoIP, and video streaming. Its lack of handshaking makes it also useful for DoS amplification attacks and DNS tunneling.`,
      icmp: `ICMP (Internet Control Message Protocol)${countStr} handles network diagnostic messages like ping and traceroute. Excessive ICMP traffic can indicate network scanning (Nmap ICMP sweeps) or ICMP flood DoS attacks.`,
      dns: `DNS protocol traffic${countStr}. In Suricata, DNS is treated as an application-layer protocol. High DNS volumes, unusual query types (TXT, NULL), or queries to rare domains may indicate DNS tunneling or DGA-based malware.`,
      http: `HTTP traffic${countStr} — unencrypted web protocol. In a controlled lab environment its presence is expected, but in production, sensitive data should always be transmitted over HTTPS. HTTP is also the channel of choice for many web-based attacks.`,
      tls: `TLS/SSL traffic${countStr}. Most modern web and application traffic is encrypted via TLS. While this protects data in transit, encrypted C2 channels and exfiltration can hide within TLS flows. Certificate metadata and JA3 fingerprints help identify suspicious actors.`,
    };

    return protos[t] ?? `Protocol "${term}"${countStr}. Network protocols define the rules for data exchange between systems. Each protocol has specific attack vectors — understanding the protocol helps analysts identify what kinds of threats are possible in this traffic.`;
  }

  // --- Metric ---
  private explainMetric(term: string, ctx: Record<string, unknown>, countStr: string): string {
    return `This time-series metric shows "${term}" over the capture window${countStr}.\n\nSpikes in alert counts often correspond to specific attack phases — an initial reconnaissance burst, a sustained brute-force, or a short but intense exploitation attempt. Correlate the spike timing with other event types (flow, DNS, HTTP) to reconstruct the attacker's timeline.\n\nFlat periods indicate either no attack activity or that the IDS rules did not match the traffic at that time. The absence of alerts does not guarantee absence of threats.`;
  }

  // --- Threat Intel ---
  private explainThreatIntel(term: string, ctx: Record<string, unknown>): string {
    const status = ctx['status'] as string | undefined;
    const malicious = ctx['malicious'] as boolean | undefined;
    const score = ctx['confidenceScore'] as number | undefined;
    const cats = ctx['threatCategories'] as string[] | undefined;
    const source = ctx['threatSource'] as string | undefined;

    if (status === 'not_enriched') {
      return `"${term}" was not found in the threat intelligence database.\n\nThis means no enrichment data is available — it does not confirm the indicator is safe. Private/internal IPs are excluded from external TI lookups by design. For unknown external indicators, consider querying VirusTotal, AbuseIPDB, or Shodan manually.\n\nRecommendation: Cross-reference with flow data and DNS logs to understand what traffic this indicator generated.`;
    }

    if (malicious) {
      const catList = cats?.join(', ') || 'unspecified';
      return `⚠️ "${term}" is flagged as MALICIOUS by threat intelligence sources.\n\nConfidence score: ${score ?? '?'}%\nCategories: ${catList}\nSource: ${source ?? 'unknown'}\n\nThis indicator has been observed in known malicious campaigns. Any internal host communicating with this IP or domain should be treated as potentially compromised.\n\nRecommendation: Immediately isolate any hosts that communicated with this indicator. Collect memory and disk forensics. Review logs for data exfiltration patterns. Block this indicator at the perimeter firewall.`;
    }

    return `"${term}" was checked against threat intelligence feeds and is currently marked as NOT malicious.\n\nConfidence score: ${score ?? 0}%\nSource: ${source ?? 'N/A'}\n\nNote: A clean TI verdict does not guarantee safety — indicators can be newly registered, not yet reported, or part of a "gray" infrastructure. Continue monitoring for behavioral anomalies.\n\nRecommendation: Keep enrichment data fresh by re-running the Python enrichment script regularly.`;
  }

  // --- Action ---
  private explainAction(term: string, ctx: Record<string, unknown>): string {
    const sig = ctx['signature'] as string | undefined;
    const cat = ctx['category'] as string | undefined;
    const context = sig ? ` for "${sig}"` : '';
    const t = term.toLowerCase();

    if (t === 'allowed' || t === 'alert')
      return `Action: "${term}"${context}.\n\nIn IDS (Intrusion Detection) mode, Suricata generates an alert but does NOT block the traffic — it simply records and reports it. The packet passes through to its destination.\n\nThis is the default mode for passive monitoring. To actively block malicious traffic, Suricata must be configured in IPS (Inline) mode with "drop" rules.\n\nCategory: ${cat ?? 'N/A'}. Recommendation: Review whether this traffic should have been blocked. Consider switching to IPS mode for critical network segments.`;

    if (t === 'drop' || t === 'block')
      return `Action: "${term}"${context}.\n\nSuricata is running in IPS (Intrusion Prevention) mode and actively DROPPED this packet. The connection was terminated before reaching the destination — the attack was blocked at the network level.\n\nCategory: ${cat ?? 'N/A'}. This is the desired outcome for known-malicious traffic. Verify the rule did not produce false positives by checking if legitimate traffic was affected.`;

    return `Action "${term}" — Suricata's response to the matched rule. Suricata supports several actions: alert (log only), drop (IPS block), reject (send TCP RST/ICMP unreachable), and pass (whitelist). The action determines whether traffic is blocked or only logged.`;
  }

  // --- General ---
  private explainGeneral(term: string, countStr: string): string {
    return `"${term}"${countStr} — This element was captured in your Suricata EVE log.\n\nSuricata is an open-source network IDS/IPS/NSM engine. It monitors traffic in real time, applies detection rules, and logs events in JSON Lines format (EVE log). The dashboard you are viewing parses this log to extract and visualize network security data.\n\nTo investigate further, correlate this indicator with timestamps, IP addresses, and alert categories visible in the "Recent Alerts" table. Look for patterns: repeated occurrences, escalating severity, or multiple attack categories from the same source IP.`;
  }
}
