import { describe, expect, it } from 'vitest';

import { mapAlertToDisplayCategory } from './alert-category.mapper';

describe('mapAlertToDisplayCategory', () => {
  it('classifies SYN resend stream alerts as DDOS', () => {
    expect(
      mapAlertToDisplayCategory(
        'Generic Protocol Command Decode',
        'SURICATA STREAM 3way handshake SYN resend different seq on SYN recv',
      ),
    ).toBe('DDOS');
  });

  it('classifies SSDP amplification alerts as DDOS', () => {
    expect(
      mapAlertToDisplayCategory(
        'Attempted Denial of Service',
        'ET DOS Possible SSDP Amplification Scan in Progress',
      ),
    ).toBe('DDOS');
  });

  it('classifies other stream anomalies as Man In The Middle', () => {
    expect(
      mapAlertToDisplayCategory(
        'Generic Protocol Command Decode',
        'SURICATA STREAM Packet with invalid timestamp',
      ),
    ).toBe('Man In The Middle');
  });
});
