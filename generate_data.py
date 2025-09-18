import pandas as pd
import numpy as np
import random
import string

def generate_random_string(length=10):
    """Generates a random string of fixed length."""
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

def generate_base64_like_string(length=20):
    """Generates a string that looks like base64 encoding."""
    chars = string.ascii_letters + string.digits + '+/'
    return ''.join(random.choice(chars) for i in range(length))

# --- Configuration ---
NUM_NORMAL_ENTRIES = 10000
NUM_MALICIOUS_ENTRIES = 100
print("Generating synthetic data...")

# --- 1. System Logs ---
normal_procs = ['chrome.exe', 'winword.exe', 'explorer.exe', 'svchost.exe']
files = [f'C:\\Users\\user\\Documents\\doc{i}.docx' for i in range(50)]
data = []
for _ in range(NUM_NORMAL_ENTRIES):
    proc = random.choice(normal_procs)
    data.append(['2025-09-18T10:00:00', 'DESKTOP-A', proc, random.randint(1000, 2000), 'read', random.choice(files)])

# Add malicious collection activity
for i in range(NUM_MALICIOUS_ENTRIES):
    pid = 9999 # Use a consistent malicious PID
    # Read 5 random files quickly
    for j in range(5):
      data.append(['2025-09-18T11:00:00', 'DESKTOP-B', 'powershell.exe', pid, 'read', f'C:\\Users\\admin\\secrets\\file{i}_{j}.dat'])

df_system = pd.DataFrame(data, columns=['timestamp', 'hostname', 'process_name', 'process_id', 'event_type', 'file_path'])
df_system.to_csv('synthetic_system_logs.csv', index=False)
print(f"Generated {len(df_system)} system log entries.")


# --- 2. Network Flows ---
data = []
for _ in range(NUM_NORMAL_ENTRIES):
    data.append(['2025-09-18T10:01:00', 'DESKTOP-A', random.choice(normal_procs), random.randint(1000, 2000), '8.8.8.8', random.randint(50, 1500), random.randint(1000, 20000), random.uniform(1.0, 10.0)])

# Add malicious exfiltration activity
for _ in range(NUM_MALICIOUS_ENTRIES):
    data.append(['2025-09-18T11:01:00', 'DESKTOP-B', 'powershell.exe', 9999, '104.22.19.93', random.randint(5000000, 10000000), random.randint(50, 200), random.uniform(100.0, 500.0)])

df_network = pd.DataFrame(data, columns=['timestamp', 'hostname', 'process_name', 'process_id', 'dest_ip', 'bytes_sent', 'bytes_received', 'duration'])
df_network.to_csv('synthetic_network_flows.csv', index=False)
print(f"Generated {len(df_network)} network flow entries.")


# --- 3. DNS Queries ---
normal_domains = ['google.com', 'office365.com', 'github.com', 'stackoverflow.com']
data = []
for _ in range(NUM_NORMAL_ENTRIES):
    data.append(['2025-09-18T10:02:00', 'DESKTOP-A', random.choice(normal_procs), random.randint(1000, 2000), f"www.{random.choice(normal_domains)}"])

# Add malicious DNS tunneling
for _ in range(NUM_MALICIOUS_ENTRIES):
    encoded_data = generate_base64_like_string(random.randint(25, 40))
    data.append(['2025-09-18T11:02:00', 'DESKTOP-C', 'rundll32.exe', 8888, f"{encoded_data}.malicious-domain.com"])

df_dns = pd.DataFrame(data, columns=['timestamp', 'hostname', 'process_name', 'process_id', 'query_name'])
df_dns.to_csv('synthetic_dns_queries.csv', index=False)
print(f"Generated {len(df_dns)} DNS query entries.")
print("\nDone! You can now run the CoDex script on the 'synthetic_*.csv' files.")