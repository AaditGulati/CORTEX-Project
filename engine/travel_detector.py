"""
CORTEX – Module 10: Impossible Travel Detection

Detects logins from geographically impossible locations within
a short timeframe using IP geolocation and Haversine distance.

Uses free ip-api.com endpoint for geolocation.
Skips check for private/localhost IPs.
"""

import math
import requests
from database import get_db_connection
from config import IMPOSSIBLE_TRAVEL_KM, IMPOSSIBLE_TRAVEL_MINUTES
from datetime import datetime, timedelta


# Private/localhost IP prefixes to skip
PRIVATE_IP_PREFIXES = (
    "127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.", "0.0.0.0", "localhost", "::1"
)


def check_impossible_travel(user_id, ip_address):
    """
    Detect impossible travel by comparing current login location
    with cached last known location.

    Args:
        user_id: The user's database ID.
        ip_address: The current request IP address.

    Returns:
        dict or None: Triggered rule dict if impossible travel detected.
    """
    # Skip private/localhost IPs
    if _is_private_ip(ip_address):
        return None

    # Get geolocation for current IP
    current_location = _get_ip_location(ip_address)
    if not current_location:
        return None

    # Get cached last known location
    last_location = _get_cached_location(user_id)

    # Update cache with current location
    _update_location_cache(
        user_id, ip_address,
        current_location["lat"], current_location["lon"],
        current_location["city"], current_location["country"]
    )

    # If no previous location, nothing to compare
    if not last_location:
        return None

    # Calculate distance and time difference
    distance_km = _haversine(
        last_location["lat"], last_location["lon"],
        current_location["lat"], current_location["lon"]
    )

    time_diff_minutes = _get_time_diff_minutes(last_location["last_seen"])

    # Check impossibility condition
    if distance_km > IMPOSSIBLE_TRAVEL_KM and time_diff_minutes < IMPOSSIBLE_TRAVEL_MINUTES:
        return {
            "name": "Impossible Travel",
            "weight": 40,
            "detail": (
                f"Login from {current_location['city']}, {current_location['country']} "
                f"({distance_km:.0f} km from {last_location['city']}, "
                f"{last_location['country']}) within {time_diff_minutes:.0f} minutes"
            )
        }

    return None


def _is_private_ip(ip_address):
    """Check if IP is a private/localhost address."""
    if not ip_address:
        return True
    return any(ip_address.startswith(prefix) for prefix in PRIVATE_IP_PREFIXES)


def _get_ip_location(ip_address):
    """
    Get geolocation data from ip-api.com (free, no API key needed).
    Returns dict with lat, lon, city, country or None on failure.
    """
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip_address}",
            timeout=5
        )

        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "lat": data.get("lat", 0.0),
                    "lon": data.get("lon", 0.0),
                    "city": data.get("city", "Unknown"),
                    "country": data.get("country", "Unknown")
                }
    except (requests.RequestException, ValueError):
        pass

    return None


def _get_cached_location(user_id):
    """Retrieve last known location from user_location_cache."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT last_ip, last_lat, last_lon, last_city, last_country, last_seen
        FROM user_location_cache
        WHERE user_id = ?
    """, (user_id,))

    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        "ip": row["last_ip"],
        "lat": row["last_lat"],
        "lon": row["last_lon"],
        "city": row["last_city"],
        "country": row["last_country"],
        "last_seen": row["last_seen"]
    }


def _update_location_cache(user_id, ip_address, lat, lon, city, country):
    """Insert or update user_location_cache with current location."""
    conn = get_db_connection()
    cursor = conn.cursor()

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO user_location_cache
        (user_id, last_ip, last_lat, last_lon, last_city, last_country, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            last_ip = ?,
            last_lat = ?,
            last_lon = ?,
            last_city = ?,
            last_country = ?,
            last_seen = ?
    """, (
        user_id, ip_address, lat, lon, city, country, now,
        ip_address, lat, lon, city, country, now
    ))

    conn.commit()
    conn.close()


def _haversine(lat1, lon1, lat2, lon2):
    """
    Calculate the great-circle distance between two points
    on the Earth using the Haversine formula (pure Python).

    Args:
        lat1, lon1: Latitude and longitude of point 1 (degrees).
        lat2, lon2: Latitude and longitude of point 2 (degrees).

    Returns:
        float: Distance in kilometers.
    """
    R = 6371.0  # Earth's radius in kilometers

    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)

    a = (
        math.sin(dlat / 2) ** 2 +
        math.cos(lat1_rad) * math.cos(lat2_rad) *
        math.sin(dlon / 2) ** 2
    )

    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    return R * c


def _get_time_diff_minutes(last_seen_str):
    """
    Calculate time difference in minutes between now and last_seen timestamp.
    """
    try:
        last_seen = datetime.strptime(last_seen_str, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return float("inf")

    diff = datetime.utcnow() - last_seen
    return diff.total_seconds() / 60.0
