import pandas as pd
from sklearn.ensemble import IsolationForest
import math
from collections import Counter

# --- Mock Cyber Threat Intelligence (CTI) Feed ---
# In a real system, this would come from a threat intelligence platform.
MOCK_CTI = [
    {
        'type': 'C2 Server',
        'ip': '104.22.19.93',
        'process_name': 'powershell.exe'
    },
    {
        'type': 'Malicious Domain',
        'domain': 'malicious-domain.com',
        'process_name': None
    }
]

def detect_data_collection(log_file_path, file_count_threshold=2, ratio_threshold=3.0):
    """Detects potential data collection behavior from system logs."""
    print("--- Running Data Collection Detector ---")
    try:
        df = pd.read_csv(log_file_path)
    except FileNotFoundError:
        return None
    # Added 'hostname' to the grouping to identify the source machine
    process_groups = df.groupby(['hostname', 'process_name', 'process_id'])
    anomalous_events = []
    for (hostname, process_name, process_id), group in process_groups:
        file_access_count = group['file_path'].nunique()
        read_count = group[group['event_type'] == 'read'].shape[0]
        write_count = group[group['event_type'] == 'write'].shape[0]
        read_write_ratio = read_count / write_count if write_count > 0 else float('inf')
        
        is_anomalous = False
        reason = ""

        if file_access_count > file_count_threshold:
            is_anomalous = True
            reason += f"Accessed {file_access_count} files (threshold > {file_count_threshold}). "
        if read_write_ratio > ratio_threshold:
            is_anomalous = True
            ratio_str = f"{read_write_ratio:.2f}" if read_write_ratio != float('inf') else "inf"
            reason += f"Read/Write ratio of {ratio_str} (threshold > {ratio_threshold})."
            
        if is_anomalous:
            # Get the latest timestamp for this process group
            latest_ts = group['timestamp'].max() if 'timestamp' in group else None
            event = {
                'detector': 'Data Collection',
                'hostname': hostname,
                'process_name': process_name,
                'process_id': process_id,
                'reason': reason.strip(),
                'accessed_files': list(group['file_path'].unique()),
                'timestamp': latest_ts
            }
            anomalous_events.append(event)
            
    return anomalous_events

def add_data_collection_warnings(collection_events, net_df, cti_feed):
    """Adds threat levels to data collection events based on CTI (Algorithm 1)."""
    print("\n--- Applying CTI to Data Collection Alerts (Algorithm 1) ---")
    for event in collection_events:
        event['threat_level'] = 'Low' # Default threat level
        
        # Get the IP address used by this process from the network logs
        proc_connections = net_df[
            (net_df['hostname'] == event['hostname']) &
            (net_df['process_name'] == event['process_name']) &
            (net_df['process_id'] == event['process_id'])
        ]
        proc_ip = proc_connections['dest_ip'].iloc[0] if not proc_connections.empty else None

        # Correlate with CTI
        for cti_entry in cti_feed:
            ip_match = cti_entry.get('ip') and cti_entry['ip'] == proc_ip
            process_match = cti_entry.get('process_name') and cti_entry['process_name'] == event['process_name']
            
            if ip_match and process_match:
                event['threat_level'] = 'High'
                event['reason'] += f" [CTI MATCH: Process and IP {proc_ip} are known threats.]"
                break # Stop checking CTI once we have a high threat
            elif ip_match and event['threat_level'] != 'High': # Don't downgrade from High
                event['threat_level'] = 'Medium'
                event['reason'] += f" [CTI MATCH: IP {proc_ip} is a known threat.]"

    # Now we print the enriched alerts
    for event in collection_events:
         print(f"ALERT (Threat: {event['threat_level']}): Suspicious data collection by '{event['process_name']}' (PID: {event['process_id']}) on host {event['hostname']}")
         print(f"  -> Reason: {event['reason']}")

    return collection_events

def generate_exfiltration_warnings(collection_events, net_df, dns_df):
    """Generates early warnings for potential exfiltration (Algorithm 2)."""
    print("\n--- Early Warning of Data Exfiltration (Algorithm 2) ---")
    warnings = []
    for event in collection_events:
        proc_key = (event['hostname'], event['process_name'], event['process_id'])
        
        # Check if this process performed ANY network or DNS activity
        net_activity = not net_df[(net_df['hostname'] == proc_key[0]) & (net_df['process_name'] == proc_key[1]) & (net_df['process_id'] == proc_key[2])].empty
        dns_activity = not dns_df[(dns_df['hostname'] == proc_key[0]) & (dns_df['process_name'] == proc_key[1]) & (dns_df['process_id'] == proc_key[2])].empty
        
        if net_activity or dns_activity:
            # Get latest timestamp from network or DNS activity
            ts_net = net_df[(net_df['hostname'] == proc_key[0]) & (net_df['process_name'] == proc_key[1]) & (net_df['process_id'] == proc_key[2])]['timestamp']
            ts_dns = dns_df[(dns_df['hostname'] == proc_key[0]) & (dns_df['process_name'] == proc_key[1]) & (dns_df['process_id'] == proc_key[2])]['timestamp']
            latest_ts = None
            if not ts_net.empty and not ts_dns.empty:
                latest_ts = max(ts_net.max(), ts_dns.max())
            elif not ts_net.empty:
                latest_ts = ts_net.max()
            elif not ts_dns.empty:
                latest_ts = ts_dns.max()
            warning = {
                'threat_level': 'High',
                'process_name': proc_key[1],
                'process_id': proc_key[2],
                'hostname': proc_key[0],
                'reason': 'Process initiated network/DNS activity after suspicious data collection.',
                'timestamp': latest_ts
            }
            warnings.append(warning)
            print(f"EARLY WARNING (Threat: {warning['threat_level']}): Potential exfiltration by '{warning['process_name']}' (PID: {warning['process_id']})")
            print(f"  -> Reason: {warning['reason']}")
    if not warnings:
        print("No early exfiltration warnings generated.")
    return warnings

def detect_http_exfiltration(df):
    """Detects potential data exfiltration over HTTP/HTTPS using an Isolation Forest model."""
    print("\n--- Running HTTP/HTTPS Exfiltration Detector ---")
    features = ['bytes_sent', 'bytes_received', 'duration']
    df_features = df[features]
    model = IsolationForest(contamination='auto', random_state=42)
    model.fit(df_features)
    predictions = model.predict(df_features)
    anomalous_indices = [i for i, pred in enumerate(predictions) if pred == -1]
    anomalous_events = []
    if anomalous_indices:
        print(f"ALERT: {len(anomalous_indices)} potential exfiltration event(s) detected!")
        for index in anomalous_indices:
            anomaly = df.iloc[index]
            event = {
                'detector': 'HTTP/HTTPS Exfiltration',
                'process_name': anomaly['process_name'],
                'process_id': anomaly['process_id'],
                'reason': f"Anomalous network flow (Bytes Sent: {anomaly['bytes_sent']}, Bytes Received: {anomaly['bytes_received']})",
                'timestamp': anomaly['timestamp'] if 'timestamp' in anomaly else None
            }
            anomalous_events.append(event)
            print(f"  -> Process '{event['process_name']}' (PID: {event['process_id']}) to dest_ip {anomaly['dest_ip']}")
    else:
        print("No suspicious HTTP/HTTPS exfiltration events detected.")
    return anomalous_events

def calculate_entropy(s):
    """Calculates the Shannon entropy of a string."""
    if not s: return 0
    p, lns = Counter(s), float(len(s))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

def detect_dns_exfiltration(df):
    """Detects potential data exfiltration over DNS using an Isolation Forest model."""
    print("\n--- Running DNS Exfiltration Detector ---")
    df['query_length'] = df['query_name'].str.len()
    df['subdomain_length'] = df['query_name'].apply(lambda x: len(x.split('.')[:-2]))
    df['numeric_ratio'] = df['query_name'].apply(lambda x: sum(c.isdigit() for c in x) / len(x))
    df['entropy'] = df['query_name'].apply(calculate_entropy)
    features = ['query_length', 'subdomain_length', 'numeric_ratio', 'entropy']
    df_features = df[features]
    model = IsolationForest(contamination='auto', random_state=42)
    model.fit(df_features)
    predictions = model.predict(df_features)
    anomalous_indices = [i for i, pred in enumerate(predictions) if pred == -1]
    anomalous_events = []
    if anomalous_indices:
        print(f"ALERT: {len(anomalous_indices)} potential DNS exfiltration event(s) detected!")
        for index in anomalous_indices:
            anomaly = df.iloc[index]
            event = {
                'detector': 'DNS Exfiltration',
                'process_name': anomaly['process_name'],
                'process_id': anomaly['process_id'],
                'reason': f"Anomalous DNS query (Query: {anomaly['query_name']}, Entropy: {anomaly['entropy']:.2f})",
                'timestamp': anomaly['timestamp'] if 'timestamp' in anomaly else None
            }
            anomalous_events.append(event)
            print(f"  -> Process '{event['process_name']}' (PID: {event['process_id']}) sent suspicious query.")
    else:
        print("No suspicious DNS exfiltration events detected.")
    return anomalous_events

def correlate_events(collection_events, network_events, dns_events):
    """Correlates events from different detectors to find high-confidence threats."""
    print("\n" + "="*50)
    print("--- Cross-Tactic Correlation Report ---")
    print("="*50)
    high_confidence_incidents = []
    net_events_by_proc = {(e['process_name'], e['process_id']): e for e in network_events}
    dns_events_by_proc = {(e['process_name'], e['process_id']): e for e in dns_events}
    for collection_event in collection_events:
        proc_key = (collection_event['process_name'], collection_event['process_id'])
        if proc_key in net_events_by_proc:
            net_event = net_events_by_proc[proc_key]
            incident = {
                'process_name': proc_key[0], 'process_id': proc_key[1],
                'summary': 'Process performed suspicious data collection followed by anomalous network exfiltration.',
                'collection_details': collection_event['reason'], 'network_details': net_event['reason']
            }
            high_confidence_incidents.append(incident)
        if proc_key in dns_events_by_proc:
            dns_event = dns_events_by_proc[proc_key]
            incident = {
                'process_name': proc_key[0], 'process_id': proc_key[1],
                'summary': 'Process performed suspicious data collection followed by anomalous DNS exfiltration.',
                'collection_details': collection_event['reason'], 'dns_details': dns_event['reason']
            }
            high_confidence_incidents.append(incident)
    if high_confidence_incidents:
        print(f"\n[!] {len(high_confidence_incidents)} HIGH-CONFIDENCE INCIDENT(S) DETECTED:\n")
        for i, incident in enumerate(high_confidence_incidents, 1):
            print(f"--- Incident #{i} ---")
            print(f"  Process: {incident['process_name']} (PID: {incident['process_id']})")
            print(f"  Summary: {incident['summary']}")
            print(f"  Evidence 1 (Collection): {incident['collection_details']}")
            if 'network_details' in incident: print(f"  Evidence 2 (Network): {incident['network_details']}")
            if 'dns_details' in incident: print(f"  Evidence 2 (DNS): {incident['dns_details']}")
            print("-" * 20)
    else:
        print("\nNo high-confidence correlated incidents found.")
    print("\nReview individual, uncorrelated alerts for situational awareness.")
    print("="*50)

# --- Main execution block ---
if __name__ == "__main__":
    # --- Configuration: Choose which dataset to use ---
    # To use the original small mock files:
    # system_log_file = 'system_logs.csv'
    # network_log_file = 'network_flows.csv'
    # dns_log_file = 'dns_queries.csv'

    # To use the large synthetic files generated by `generate_data.py`:
    system_log_file = 'synthetic_system_logs.csv'
    network_log_file = 'synthetic_network_flows.csv'
    dns_log_file = 'synthetic_dns_queries.csv'
    
    # --- Script Execution ---
    print(f"Analyzing logs: {system_log_file}, {network_log_file}, {dns_log_file}\n")

    try:
        net_df = pd.read_csv(network_log_file)
        dns_df = pd.read_csv(dns_log_file)
    except FileNotFoundError as e:
        print(f"Error loading data files: {e}. Please ensure CSV files are present.")
        exit()

    # --- Phase 1: Initial Detection & Early Warnings ---
    collection_events = detect_data_collection(system_log_file)
    
    if collection_events:
        enriched_collection_events = add_data_collection_warnings(collection_events, net_df, MOCK_CTI)
        generate_exfiltration_warnings(enriched_collection_events, net_df, dns_df)
    else:
        enriched_collection_events = []
        print("\nNo data collection events to generate warnings from.")

    # --- Phase 2: Exfiltration Detection ---
    suspicious_network_events = detect_http_exfiltration(net_df)
    suspicious_dns_events = detect_dns_exfiltration(dns_df)
    
    # --- Phase 3: Final Correlation ---
    correlate_events(enriched_collection_events, suspicious_network_events, suspicious_dns_events)