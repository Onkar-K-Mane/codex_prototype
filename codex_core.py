import pandas as pd
from sklearn.ensemble import IsolationForest
from codex_utils import calculate_entropy

from codex_data_collection import detect_data_collection
from codex_exfiltration import generate_exfiltration_warnings, detect_http_exfiltration, detect_dns_exfiltration
from codex_correlation import correlate_events

# CTI enrichment moved to codex_cti.py

def generate_exfiltration_warnings(collection_events, net_df, dns_df):
    """
    Generates early warnings for potential data exfiltration by checking if any process
    that performed suspicious data collection also initiated network or DNS activity.
    Returns a list of warning events with threat level and reason.
    """
    warnings = []
    for event in collection_events:
        # Extract process identity
        proc_key = (event['hostname'], event['process_name'], event['process_id'])
        # Check for network and DNS activity
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
    return warnings

def detect_http_exfiltration(df):
    """
    Detects potential data exfiltration over HTTP/HTTPS using an Isolation Forest anomaly detection model.
    Returns a list of anomalous network events.
    """
    features = ['bytes_sent', 'bytes_received', 'duration']
    df_features = df[features]
    model = IsolationForest(contamination='auto', random_state=42)
    model.fit(df_features)
    predictions = model.predict(df_features)
    anomalous_indices = [i for i, pred in enumerate(predictions) if pred == -1]
    anomalous_events = []
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
    return anomalous_events

# Use calculate_entropy from codex_utils.py

def detect_dns_exfiltration(df):
    """
    Detects potential data exfiltration over DNS using an Isolation Forest anomaly detection model.
    Returns a list of anomalous DNS events.
    """
    # Feature engineering for DNS queries
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
    return anomalous_events

def correlate_events(collection_events, network_events, dns_events):
    """
    Correlates events from different detectors to find high-confidence threats.
    Returns a list of incidents where a process performed suspicious data collection followed by network or DNS exfiltration.
    """
    high_confidence_incidents = []
    # Index network and DNS events by process identity
    net_events_by_proc = {(e['process_name'], e['process_id']): e for e in network_events}
    dns_events_by_proc = {(e['process_name'], e['process_id']): e for e in dns_events}
    for collection_event in collection_events:
        proc_key = (collection_event['process_name'], collection_event['process_id'])
        # Correlate with network exfiltration
        if proc_key in net_events_by_proc:
            net_event = net_events_by_proc[proc_key]
            incident = {
                'process_name': proc_key[0],
                'process_id': proc_key[1],
                'summary': 'Process performed suspicious data collection followed by anomalous network exfiltration.',
                'collection_details': collection_event['reason'],
                'network_details': net_event['reason'],
                'timestamp': max(collection_event.get('timestamp',''), net_event.get('timestamp',''))
            }
            high_confidence_incidents.append(incident)
        # Correlate with DNS exfiltration
        if proc_key in dns_events_by_proc:
            dns_event = dns_events_by_proc[proc_key]
            incident = {
                'process_name': proc_key[0],
                'process_id': proc_key[1],
                'summary': 'Process performed suspicious data collection followed by anomalous DNS exfiltration.',
                'collection_details': collection_event['reason'],
                'dns_details': dns_event['reason'],
                'timestamp': max(collection_event.get('timestamp',''), dns_event.get('timestamp',''))
            }
            high_confidence_incidents.append(incident)
    return high_confidence_incidents
