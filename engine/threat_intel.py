"""
CORTEX – Module 12: Threat Intelligence Feed

Checks login IPs against known malicious IP ranges and Tor exit nodes
using a local database seeded with public threat intelligence data.
Supports CIDR range matching using pure Python (no external libraries).
"""

import struct
import socket
from database import get_db_connection
from datetime import datetime


# -----------------------------------------------
# Hardcoded seed data: known malicious CIDR ranges
# Sources: Public botnet trackers, Tor exit node lists
# -----------------------------------------------
SEED_THREAT_DATA = [
    # Known Tor exit node ranges (examples from check.torproject.org)
    {"ip_range": "185.220.100.0/24", "threat_type": "TOR_EXIT", "source": "torproject.org"},
    {"ip_range": "185.220.101.0/24", "threat_type": "TOR_EXIT", "source": "torproject.org"},
    {"ip_range": "185.220.102.0/24", "threat_type": "TOR_EXIT", "source": "torproject.org"},
    {"ip_range": "199.249.230.0/24", "threat_type": "TOR_EXIT", "source": "torproject.org"},
    {"ip_range": "204.85.191.0/24", "threat_type": "TOR_EXIT", "source": "torproject.org"},
    {"ip_range": "109.70.100.0/24", "threat_type": "TOR_EXIT", "source": "torproject.org"},
    {"ip_range": "51.15.0.0/16", "threat_type": "TOR_EXIT", "source": "torproject.org"},

    # Known botnet/scanner ranges
    {"ip_range": "45.148.10.0/24", "threat_type": "BOTNET", "source": "abuse.ch"},
    {"ip_range": "193.42.33.0/24", "threat_type": "BOTNET", "source": "abuse.ch"},
    {"ip_range": "91.243.44.0/24", "threat_type": "SCANNER", "source": "blocklist.de"},
    {"ip_range": "185.56.80.0/24", "threat_type": "SCANNER", "source": "blocklist.de"},
    {"ip_range": "194.26.192.0/24", "threat_type": "BRUTE_FORCE", "source": "blocklist.de"},
    {"ip_range": "5.188.206.0/24", "threat_type": "BRUTE_FORCE", "source": "blocklist.de"},

    # Known malicious hosting ranges
    {"ip_range": "23.129.64.0/24", "threat_type": "TOR_EXIT", "source": "torproject.org"},
    {"ip_range": "171.25.193.0/24", "threat_type": "TOR_EXIT", "source": "torproject.org"},
]


def seed_threat_feeds():
    """
    Seed the threat_feeds table with hardcoded known malicious IP ranges.
    Only inserts if the table is empty (prevents duplicates on restart).
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if already seeded
    cursor.execute("SELECT COUNT(*) as cnt FROM threat_feeds")
    count = cursor.fetchone()["cnt"]

    if count == 0:
        for entry in SEED_THREAT_DATA:
            cursor.execute("""
                INSERT INTO threat_feeds (ip_range, threat_type, source)
                VALUES (?, ?, ?)
            """, (entry["ip_range"], entry["threat_type"], entry["source"]))

        conn.commit()
        print(f"[CORTEX] Seeded {len(SEED_THREAT_DATA)} threat intel entries.")

    conn.close()


def check_threat_intel(ip_address):
    """
    Check if login IP matches any known malicious IP range.

    Args:
        ip_address: The request IP address.

    Returns:
        dict or None: Triggered rule dict if IP matches a threat feed entry.
    """
    # Skip private/localhost IPs
    if not ip_address or ip_address.startswith(("127.", "10.", "192.168.", "0.0.0.0")):
        return None

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT ip_range, threat_type, source FROM threat_feeds")
    feeds = cursor.fetchall()
    conn.close()

    for feed in feeds:
        if _ip_in_cidr(ip_address, feed["ip_range"]):
            return {
                "name": "Threat Intel Hit",
                "weight": 35,
                "detail": (
                    f"IP {ip_address} matches threat feed: "
                    f"{feed['threat_type']} (source: {feed['source']}, "
                    f"range: {feed['ip_range']})"
                )
            }

    return None


def refresh_threat_feeds():
    """
    Refresh threat feeds by re-seeding with updated data.
    Clears existing entries and re-inserts the seed data.

    Returns:
        dict: { "refreshed": True, "entries": int }
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Clear existing feeds
    cursor.execute("DELETE FROM threat_feeds")

    # Re-insert seed data
    for entry in SEED_THREAT_DATA:
        cursor.execute("""
            INSERT INTO threat_feeds (ip_range, threat_type, source)
            VALUES (?, ?, ?)
        """, (entry["ip_range"], entry["threat_type"], entry["source"]))

    conn.commit()
    conn.close()

    return {
        "refreshed": True,
        "entries": len(SEED_THREAT_DATA),
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    }


def _ip_in_cidr(ip_address, cidr):
    """
    Check if an IP address falls within a CIDR range.
    Pure Python implementation — no external libraries.

    Args:
        ip_address: IP address string (e.g., "185.220.100.42").
        cidr: CIDR notation string (e.g., "185.220.100.0/24").

    Returns:
        bool: True if IP is within the CIDR range.
    """
    try:
        # Parse CIDR
        if "/" in cidr:
            network_str, prefix_len = cidr.split("/")
            prefix_len = int(prefix_len)
        else:
            network_str = cidr
            prefix_len = 32

        # Convert IPs to integers
        ip_int = _ip_to_int(ip_address)
        network_int = _ip_to_int(network_str)

        if ip_int is None or network_int is None:
            return False

        # Create mask and compare
        mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
        return (ip_int & mask) == (network_int & mask)

    except (ValueError, TypeError):
        return False


def _ip_to_int(ip_address):
    """Convert an IP address string to a 32-bit integer."""
    try:
        packed = socket.inet_aton(ip_address)
        return struct.unpack("!I", packed)[0]
    except (OSError, struct.error):
        return None
