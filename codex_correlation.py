# codex_correlation.py

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
