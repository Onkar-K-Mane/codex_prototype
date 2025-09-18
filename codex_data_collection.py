# codex_data_collection.py
import pandas as pd

def detect_data_collection(log_file_path, file_count_threshold=2, ratio_threshold=3.0):
    """
    Detects potential data collection behavior from system logs.
    Groups log entries by process and flags those that access many files or have a high read/write ratio.
    Returns a list of anomalous events with details and timestamp.
    """
    try:
        df = pd.read_csv(log_file_path)
    except FileNotFoundError:
        return None
    # Group by host, process name, and process ID
    process_groups = df.groupby(['hostname', 'process_name', 'process_id'])
    anomalous_events = []
    for (hostname, process_name, process_id), group in process_groups:
        file_access_count = group['file_path'].nunique()
        read_count = group[group['event_type'] == 'read'].shape[0]
        write_count = group[group['event_type'] == 'write'].shape[0]
        read_write_ratio = read_count / write_count if write_count > 0 else float('inf')
        is_anomalous = False
        reason = ""
        # Flag if accessed too many files
        if file_access_count > file_count_threshold:
            is_anomalous = True
            reason += f"Accessed {file_access_count} files (threshold > {file_count_threshold}). "
        # Flag if read/write ratio is suspicious
        if read_write_ratio > ratio_threshold:
            is_anomalous = True
            ratio_str = f"{read_write_ratio:.2f}" if read_write_ratio != float('inf') else "inf"
            reason += f"Read/Write ratio of {ratio_str} (threshold > {ratio_threshold})."
        if is_anomalous:
            # Use latest timestamp for this process group
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
