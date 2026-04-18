"""
CORTEX – Configuration Constants
"""

DATABASE = "cortex.db"
SECRET_KEY = "supersecretkey"
ADMIN_TOKEN = "cortex-admin-2025"

# Module 7 – Risk Decay
DECAY_FACTOR = 10

# Module 9 – Velocity Detection
VELOCITY_IP_WINDOW_MINUTES = 60
VELOCITY_IP_THRESHOLD = 10
VELOCITY_USER_THRESHOLD = 8

# Module 10 – Impossible Travel
IMPOSSIBLE_TRAVEL_KM = 500
IMPOSSIBLE_TRAVEL_MINUTES = 60
