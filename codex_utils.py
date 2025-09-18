# codex_utils.py
import math
from collections import Counter

def calculate_entropy(s):
    """
    Calculates the Shannon entropy of a string.
    Used to measure randomness in DNS queries for exfiltration detection.
    """
    if not s:
        return 0
    p, lns = Counter(s), float(len(s))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())
