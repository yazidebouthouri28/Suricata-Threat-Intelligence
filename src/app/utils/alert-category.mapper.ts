/** User-facing alert category labels shown in the dashboard. */
export type DisplayAlertCategory =
  | 'DOS'
  | 'DDOS'
  | 'BRUTE FORCE'
  | 'PRIVILEGE ESCALATION'
  | 'UDP FLOOD'
  | 'Man In The Middle'
  | 'SQL Injection'
  | 'Reconnaissance';

const DISPLAY_CATEGORIES: DisplayAlertCategory[] = [
  'DOS',
  'DDOS',
  'BRUTE FORCE',
  'PRIVILEGE ESCALATION',
  'UDP FLOOD',
  'Man In The Middle',
  'SQL Injection',
  'Reconnaissance',
];

/**
 * Maps Suricata alert metadata to short, readable category names for analysts.
 */
export function mapAlertToDisplayCategory(
  suricataCategory: string,
  signature: string,
): DisplayAlertCategory {
  const category = suricataCategory.toLowerCase();
  const sig = signature.toLowerCase();

  if (matchesSqlInjection(sig, category)) {
    return 'SQL Injection';
  }

  if (matchesUdpFlood(sig)) {
    return 'UDP FLOOD';
  }

  if (matchesDdos(sig, category)) {
    return 'DDOS';
  }

  if (matchesDos(sig, category)) {
    return 'DOS';
  }

  if (matchesBruteForce(sig, category)) {
    return 'BRUTE FORCE';
  }

  if (matchesPrivilegeEscalation(sig, category)) {
    return 'PRIVILEGE ESCALATION';
  }

  if (matchesManInTheMiddle(sig, category)) {
    return 'Man In The Middle';
  }

  if (matchesReconnaissance(sig, category)) {
    return 'Reconnaissance';
  }

  if (category.includes('web application attack')) {
    return mapWebApplicationAttack(sig);
  }

  if (category.includes('generic protocol command decode')) {
    return 'Man In The Middle';
  }

  if (category.includes('misc activity')) {
    return 'Reconnaissance';
  }

  return 'Reconnaissance';
}

export function isDisplayAlertCategory(value: string): value is DisplayAlertCategory {
  return DISPLAY_CATEGORIES.includes(value as DisplayAlertCategory);
}

function matchesSqlInjection(sig: string, category: string): boolean {
  return (
    sig.includes('sql injection') ||
    sig.includes('sqli') ||
    sig.includes('sql inject') ||
    sig.includes('command injection') ||
    sig.includes('os command injection') ||
    category.includes('sql injection')
  );
}

function matchesUdpFlood(sig: string): boolean {
  return sig.includes('udp flood') || (sig.includes('udp') && sig.includes('flood'));
}

function matchesDdos(sig: string, category: string): boolean {
  return (
    sig.includes('ddos') ||
    sig.includes('amplification') ||
    sig.includes('ssdp amplification') ||
    category.includes('distributed denial') ||
    sig.includes('syn flood') ||
    sig.includes('syn resend') ||
    (sig.includes('3way handshake') && sig.includes('syn'))
  );
}

function matchesDos(sig: string, category: string): boolean {
  return (
    sig.includes(' et dos ') ||
    sig.startsWith('et dos') ||
    category.includes('attempted denial of service') ||
    (category.includes('denial of service') && !category.includes('distributed'))
  );
}

function matchesBruteForce(sig: string, category: string): boolean {
  return (
    sig.includes('brute force') ||
    sig.includes('default credential') ||
    sig.includes('default password') ||
    sig.includes('credential stuffing') ||
    category.includes('credential theft') ||
    category.includes('successful credential theft')
  );
}

function matchesPrivilegeEscalation(sig: string, category: string): boolean {
  return (
    category.includes('administrator privilege gain') ||
    category.includes('user privilege gain') ||
    category.includes('attempted administrator privilege gain') ||
    category.includes('attempted user privilege gain') ||
    sig.includes('privilege escalation') ||
    sig.includes('administrator access') ||
    sig.includes('arbitrary code execution') ||
    sig.includes('remote code execution') ||
    sig.includes('path traversal') ||
    (sig.includes('exploit') && sig.includes('cve'))
  );
}

function matchesManInTheMiddle(sig: string, category: string): boolean {
  return (
    sig.includes('man in the middle') ||
    sig.includes('mitm') ||
    sig.includes('protocol only one direction') ||
    sig.includes('3way handshake') ||
    sig.includes('invalid timestamp') ||
    sig.includes('stream ') ||
    category.includes('generic protocol command decode')
  );
}

function matchesReconnaissance(sig: string, category: string): boolean {
  return (
    sig.includes('nmap') ||
    sig.includes('scan') ||
    sig.includes('scanner') ||
    category.includes('attempted recon')
  );
}

function mapWebApplicationAttack(sig: string): DisplayAlertCategory {
  if (matchesSqlInjection(sig, '')) {
    return 'SQL Injection';
  }
  if (matchesBruteForce(sig, '')) {
    return 'BRUTE FORCE';
  }
  if (matchesReconnaissance(sig, '')) {
    return 'Reconnaissance';
  }
  if (matchesPrivilegeEscalation(sig, '')) {
    return 'PRIVILEGE ESCALATION';
  }
  return 'Reconnaissance';
}
