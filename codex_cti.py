# codex_cti.py

MOCK_CTI = [
    # Example threat intelligence feed entries
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

def add_data_collection_warnings(collection_events, net_df, cti_feed):
    """
    Adds threat levels to data collection events based on CTI (Cyber Threat Intelligence).
    Updates each event with a threat level and reason if a CTI match is found.
    """
    for event in collection_events:
        event['threat_level'] = 'Low'  # Default threat level
        # Get the IP address used by this process from the network logs
        proc_connections = net_df[
            (net_df['hostname'] == event['hostname']) &
            (net_df['process_name'] == event['process_name']) &
            (net_df['process_id'] == event['process_id'])
        ]
        proc_ip = proc_connections['dest_ip'].iloc[0] if not proc_connections.empty else None
        # Correlate with CTI feed
        for cti_entry in cti_feed:
            ip_match = cti_entry.get('ip') and cti_entry['ip'] == proc_ip
            process_match = cti_entry.get('process_name') and cti_entry['process_name'] == event['process_name']
            if ip_match and process_match:
                event['threat_level'] = 'High'
                event['reason'] += f" [CTI MATCH: Process and IP {proc_ip} are known threats.]"
                break  # Stop checking CTI once we have a high threat
            elif ip_match and event['threat_level'] != 'High':  # Don't downgrade from High
                event['threat_level'] = 'Medium'
                event['reason'] += f" [CTI MATCH: IP {proc_ip} is a known threat.]"
    return collection_events
