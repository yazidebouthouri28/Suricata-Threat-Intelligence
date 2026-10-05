import json
import sqlite3
import urllib.request
import urllib.error
import urllib.parse
import os
import time
import argparse
import ipaddress
import datetime
import ssl
from pathlib import Path

VT_API_KEY = os.environ.get('VT_API_KEY', '')

SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.check_hostname = False
SSL_CONTEXT.verify_mode = ssl.CERT_NONE

def is_public_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_reserved or ip.is_link_local)
    except ValueError:
        return False

def is_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def setup_db(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS cache (
            indicator TEXT PRIMARY KEY,
            data_json TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    return conn

def get_from_cache(conn, indicator):
    cur = conn.cursor()
    cur.execute("SELECT data_json, timestamp FROM cache WHERE indicator = ?", (indicator,))
    row = cur.fetchone()
    if row:
        data_json, ts_str = row
        ts = datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        if (datetime.datetime.utcnow() - ts).total_seconds() < 86400:
            return json.loads(data_json)
        else:
            cur.execute("DELETE FROM cache WHERE indicator = ?", (indicator,))
            conn.commit()
    return None

def save_to_cache(conn, indicator, data):
    cur = conn.cursor()
    cur.execute('''
        INSERT OR REPLACE INTO cache (indicator, data_json, timestamp) 
        VALUES (?, ?, datetime('now'))
    ''', (indicator, json.dumps(data)))
    conn.commit()

def query_urlhaus(indicator):
    url = "https://urlhaus-api.abuse.ch/v1/host/"
    data = urllib.parse.urlencode({'host': indicator}).encode('ascii')
    req = urllib.request.Request(url, data=data)
    try:
        with urllib.request.urlopen(req, timeout=10, context=SSL_CONTEXT) as response:
            res = json.loads(response.read().decode())
            if res.get('query_status') == 'ok' and res.get('url_count', 0) > 0:
                return {
                    'malicious': True,
                    'source': 'urlhaus',
                    'score': 90,
                    'categories': ['malware'] if 'tags' not in res else res.get('tags', []),
                    'raw': res
                }
            return {'malicious': False, 'source': 'urlhaus', 'score': 0, 'categories': [], 'raw': res}
    except Exception as e:
        print(f"Erreur URLhaus pour {indicator}: {e}")
        return None

def query_virustotal(indicator, ind_type, last_request_time):
    if not VT_API_KEY:
        return None
    
    # Respect rate limit (4 req/min => 15s between requests)
    now = time.time()
    elapsed = now - last_request_time
    if elapsed < 15.5:
        time.sleep(15.5 - elapsed)
    
    endpoint = f"ip_addresses/{indicator}" if ind_type == 'ip' else f"domains/{indicator}"
    url = f"https://www.virustotal.com/api/v3/{endpoint}"
    req = urllib.request.Request(url, headers={'x-apikey': VT_API_KEY})
    
    try:
        with urllib.request.urlopen(req, timeout=10, context=SSL_CONTEXT) as response:
            res = json.loads(response.read().decode())
            data = res.get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())
            
            score = 0
            if total > 0:
                score = round((malicious + suspicious) / total * 100)
                
            categories = []
            if 'popular_threat_classification' in data:
                categories = data['popular_threat_classification'].get('suggested_threat_labels', [])
                
            return {
                'malicious': malicious > 0 or suspicious > 0,
                'source': 'virustotal',
                'score': score,
                'categories': categories,
                'raw': res,
                'time': time.time()
            }
    except Exception as e:
        print(f"Erreur VirusTotal pour {indicator}: {e}")
        return None

def extract_indicators(filepath):
    indicators = {}
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
                
            src_ip = event.get('src_ip')
            if src_ip:
                indicators[src_ip] = 'ip'
                
            dest_ip = event.get('dest_ip')
            if dest_ip:
                indicators[dest_ip] = 'ip'
                
            dns = event.get('dns', {})
            rrname = dns.get('rrname')
            if rrname:
                indicators[rrname] = 'domain'
                
            http = event.get('http', {})
            hostname = http.get('hostname')
            if hostname:
                indicators[hostname] = 'ip' if is_ip(hostname) else 'domain'
                
    return indicators

def main():
    parser = argparse.ArgumentParser(description="Enrichissement Threat Intelligence")
    parser.add_argument('--file', default='../src/assets/eve_complet.json', help='Chemin du fichier eve_complet.json')
    parser.add_argument('--output', default='../src/assets/threat_intel.json', help='Fichier de sortie json')
    parser.add_argument('--limit', type=int, default=0, help='Limiter le nombre d\'indicateurs a traiter')
    args = parser.parse_args()

    print(f"Extraction des indicateurs de {args.file}...")
    if not os.path.exists(args.file):
        print(f"Erreur: fichier introuvable {args.file}")
        return

    indicators = extract_indicators(args.file)
    print(f"{len(indicators)} indicateurs uniques trouves.")
    
    ind_list = list(indicators.items())
    if args.limit > 0:
        ind_list = ind_list[:args.limit]
        print(f"Limitation a {args.limit} indicateurs.")

    db_path = 'threat_intel_cache.sqlite'
    conn = setup_db(db_path)
    
    results = []
    last_vt_time = 0
    
    for i, (ind, itype) in enumerate(ind_list):
        print(f"[{i+1}/{len(ind_list)}] Analyse de {ind} ({itype})...")
        
        cached = get_from_cache(conn, ind)
        if cached:
            results.append(cached)
            continue
            
        is_malicious = False
        source = 'none'
        score = 0
        categories = []
        
        # Bypass API for private IPs
        if itype == 'ip' and not is_public_ip(ind):
            source = 'local'
            score = 0
            is_malicious = False
        else:
            uh_res = query_urlhaus(ind)
            vt_res = None
            if VT_API_KEY:
                vt_res = query_virustotal(ind, itype, last_vt_time)
                if vt_res and 'time' in vt_res:
                    last_vt_time = vt_res['time']
                    del vt_res['time']
                    
            if uh_res and uh_res['malicious'] and vt_res and vt_res['malicious']:
                is_malicious = True
                source = 'virustotal+urlhaus'
                score = max(uh_res['score'], vt_res['score'])
                categories = list(set(uh_res['categories'] + vt_res['categories']))
            elif vt_res and vt_res['malicious']:
                is_malicious = True
                source = 'virustotal'
                score = vt_res['score']
                categories = vt_res['categories']
            elif uh_res and uh_res['malicious']:
                is_malicious = True
                source = 'urlhaus'
                score = uh_res['score']
                categories = uh_res['categories']
            elif vt_res:
                source = 'virustotal'
                score = vt_res['score']
        
        # fallback categories map
        cat_str_list = []
        for c in categories:
            if isinstance(c, str):
                cat_str_list.append(c)
            elif isinstance(c, dict) and 'value' in c: # sometimes VT gives dicts
                cat_str_list.append(c['value'])
                
        # cleanup categories to only strings
        cat_str_list = [str(x) for x in cat_str_list]
            
        entry = {
            'indicator': ind,
            'type': itype,
            'malicious': is_malicious,
            'threat_source': source,
            'confidence_score': score,
            'threat_categories': cat_str_list,
            'checked_at': datetime.datetime.utcnow().isoformat() + 'Z'
        }
        
        save_to_cache(conn, ind, entry)
        results.append(entry)
        
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
        
    print(f"Termine. {len(results)} resultats sauvegardes dans {args.output}")
    conn.close()

if __name__ == '__main__':
    main()
