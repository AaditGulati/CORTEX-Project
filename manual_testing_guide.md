# CORTEX — Complete Manual Testing Guide

> All commands use PowerShell `Invoke-RestMethod`. Run from `d:\CORTEX-Project`.

---

## Step 1: Fresh Start (Reset Everything)

Open **Terminal 1** and run:

```powershell
# Kill any running Flask server
taskkill /F /IM python.exe

# Wait a moment, then delete the old database
Start-Sleep -Seconds 1
del cortex.db

# Start the server fresh
python app.py
```

**Expected Output:**
```
[CORTEX] Seeded 15 threat intel entries.
 * Serving Flask app 'app'
 * Debug mode: on
 * Running on http://127.0.0.1:5000
```

Now open **Terminal 2** for all test commands below. Keep Terminal 1 running.

---

## Step 2: Register Users

### Register "aadit"
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/register" -Method Post -ContentType "application/json" -Body '{"username": "aadit", "password": "MyPass@123"}'
```

**Expected Output:**
```
status
------
REGISTERED
```

### Register "testuser"
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/register" -Method Post -ContentType "application/json" -Body '{"username": "testuser", "password": "Test@456"}'
```

**Expected Output:**
```
status
------
REGISTERED
```

### Try Duplicate Registration (should fail)
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/register" -Method Post -ContentType "application/json" -Body '{"username": "aadit", "password": "anything"}'
```

**Expected Output:**
```
status
------
EXISTS
```

**What's happening:** Module 2 (Authentication) hashes the password with SHA-256 and stores it in SQLite. Duplicate usernames are rejected.

---

## Step 3: Normal Login (Clean — No Rules Triggered)

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/login" -Method Post -ContentType "application/json" -Body '{"username": "aadit", "password": "MyPass@123"}' | ConvertTo-Json -Depth 10
```

**Expected Output:**
```json
{
    "enforcement_action": "ALLOWED",
    "explanation": {
        "decision": "ALLOWED",
        "reason_summary": "Login was permitted after risk assessment.",
        "recommended_action": "No immediate action required. Continue monitoring user activity.",
        "risk_breakdown": [],
        "severity": "LOW",
        "total_risk": 0
    },
    "risk_score": 0,
    "severity": "LOW",
    "status": "SUCCESS",
    "triggered_rules": [],
    "user_id": 1
}
```

**What's happening:** The full 13-module pipeline runs. No rules triggered, risk is 0, decision is ALLOWED. Module 3 (Baseline) records this IP, device, and login hour as the user's baseline behavior.

---

## Step 4: Wrong Password Login

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/login" -Method Post -ContentType "application/json" -Body '{"username": "aadit", "password": "WrongPassword"}' | ConvertTo-Json -Depth 10
```

**Expected Output:**
```json
{
    "enforcement_action": "ALLOWED",
    "risk_score": 0,
    "severity": "LOW",
    "status": "FAIL",
    "triggered_rules": [],
    "user_id": 1
}
```

**What's happening:** Password mismatch → `status: FAIL`. The failed attempt is logged in `login_attempts` table. Risk is still 0 because a single failure doesn't trigger brute force (requires 5+ in 5 minutes).

---

## Step 5: Test Brute Force Detection

Fire 5 failed logins rapidly (combined with Step 4's failure = 6 total):

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/login" -Method Post -ContentType "application/json" -Body '{"username": "aadit", "password": "wrong1"}'
Invoke-RestMethod -Uri "http://127.0.0.1:5000/login" -Method Post -ContentType "application/json" -Body '{"username": "aadit", "password": "wrong2"}'
Invoke-RestMethod -Uri "http://127.0.0.1:5000/login" -Method Post -ContentType "application/json" -Body '{"username": "aadit", "password": "wrong3"}'
```

**Expected:** The first 2-3 will return `status: FAIL`. At some point it returns a **403 error** because the account gets locked from cumulative risk (brute force rule + behavioral anomaly triggers).

If a command throws a red error in PowerShell, that's the 403 lock — **this is correct behavior!**

Now try logging in with the correct password:
```powershell
try {
    Invoke-RestMethod -Uri "http://127.0.0.1:5000/login" -Method Post -ContentType "application/json" -Body '{"username": "aadit", "password": "MyPass@123"}' | ConvertTo-Json -Depth 10
} catch {
    $_.ErrorDetails.Message | ConvertFrom-Json | ConvertTo-Json -Depth 10
}
```

**Expected Output:**
```json
{
    "message": "Account temporarily locked due to suspicious activity.",
    "risk_score": 52,
    "severity": "MEDIUM",
    "status": "locked",
    "triggered_rules": [
        { "risk_points": 30, "rule_name": "Brute Force" },
        { "risk_points": 20, "rule_name": "Behavioral Anomaly" }
    ],
    "explanation": {
        "decision": "LOCKED",
        "reason_summary": "Account temporarily locked due to high-risk login activity.",
        "risk_breakdown": [
            { "rule": "Brute Force", "points": 30, "explanation": "Multiple failed login attempts detected in a short time window..." },
            { "rule": "Behavioral Anomaly", "points": 20, "explanation": "Login behavior deviates significantly from the user's established baseline..." }
        ]
    }
}
```

**What's happening:**
- **Module 4 (Rules):** Detected 5+ failed logins in 5 min → `Brute Force` (+30 points)
- **Module 3 (Baseline):** Deviation from normal behavior → `Behavioral Anomaly` (+20 points)
- **Module 5 (Risk Scoring):** 30 + 20 = 50 cumulative → severity = MEDIUM
- **Module 6 (Lockdown):** Score ≥ 40 → account LOCKED for 10 minutes
- **Module 13 (Explainability):** Generated human-readable explanation of why the lock happened
- **Module 8 (Enforcement Logger):** Logged everything to `enforcement_logs` table

---

## Step 6: Unlock Account

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/admin/unlock/1" -Method Post -Headers @{"X-Admin-Token"="cortex-admin-2025"}
```

**Expected Output:**
```
status   user_id username
------   ------- --------
unlocked       1 aadit
```

**What's happening:** Admin API (Module 14) authenticates via `X-Admin-Token` header and clears the lock on user ID 1.

---

## Step 7: Test Session Fingerprinting (Different Devices)

### Login from "Chrome" (establish baseline fingerprint)
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/login" -Method Post -Headers @{"User-Agent"="Chrome/120.0"; "Accept-Language"="en-US"} -ContentType "application/json" -Body '{"username": "testuser", "password": "Test@456"}' | ConvertTo-Json -Depth 10
```

**Expected:** `risk_score: 0`, `triggered_rules: []`, `status: SUCCESS`

**What's happening:** Module 11 (Fingerprinting) creates a SHA-256 hash of the User-Agent + Accept-Language + Accept-Encoding headers. First fingerprint is saved as the baseline — no alarm raised.

### Login from "Firefox" (different device fingerprint)
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/login" -Method Post -Headers @{"User-Agent"="Firefox/99.0"; "Accept-Language"="fr-FR"} -ContentType "application/json" -Body '{"username": "testuser", "password": "Test@456"}' | ConvertTo-Json -Depth 10
```

**Expected Output:**
```json
{
    "risk_score": 15,
    "severity": "LOW",
    "status": "SUCCESS",
    "enforcement_action": "ALLOWED",
    "triggered_rules": [
        { "risk_points": 15, "rule_name": "Unknown Fingerprint" }
    ],
    "explanation": {
        "risk_breakdown": [
            { "rule": "Unknown Fingerprint", "points": 15, "explanation": "Login from an unrecognized device fingerprint..." }
        ]
    }
}
```

**What's happening:** The Firefox fingerprint hash doesn't match the stored Chrome hash → Module 11 triggers `Unknown Fingerprint` (+15 points). Score is 15 < 20 so it's still ALLOWED, but it's logged and the new fingerprint is recorded.

---

## Step 8: Test Velocity Detection

Run 10 rapid logins to exceed the velocity threshold (>8 user logins in 60 min):

```powershell
for ($i=1; $i -le 10; $i++) {
    try {
        $r = Invoke-RestMethod -Uri "http://127.0.0.1:5000/login" -Method Post -ContentType "application/json" -Body '{"username": "testuser", "password": "Test@456"}'
        Write-Host "Attempt $i : risk=$($r.risk_score) action=$($r.enforcement_action)"
    } catch {
        Write-Host "Attempt $i : BLOCKED (403 - account locked)"
    }
}
```

**Expected Output:**
```
Attempt 1 : BLOCKED (403 - account locked)
Attempt 2 : BLOCKED (403 - account locked)
...
```

**What's happening:** Cumulative risk from the fingerprint test (15) plus velocity detection (25) pushes the score above 40 → account gets locked. Every subsequent attempt just hits the lock check.

- **Module 9 (Velocity):** >10 requests from same IP in 60 min → `Velocity IP` (+25)
- **Module 6 (Lockdown):** Cumulative risk ≥ 40 → LOCKED

---

## Step 9: Unlock and Check Explainability

### Unlock testuser
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/admin/unlock/2" -Method Post -Headers @{"X-Admin-Token"="cortex-admin-2025"}
```

### Get Explanation for user "aadit" (user_id = 1)
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/explain/1/latest" | ConvertTo-Json -Depth 10
```

**Expected Output:**
```json
{
    "decision": "LOCKED",
    "log_timestamp": "2026-04-14 07:01:20",
    "reason_summary": "Account temporarily locked due to high-risk login activity.",
    "recommended_action": "Review recent login activity. Consider requiring identity verification on next login.",
    "risk_breakdown": [
        { "rule": "Brute Force", "points": 30, "explanation": "Multiple failed login attempts detected..." },
        { "rule": "Behavioral Anomaly", "points": 20, "explanation": "Login behavior deviates significantly..." }
    ],
    "severity": "MEDIUM",
    "total_risk": 52
}
```

**What's happening:** Module 13 (Explainability Engine) retrieves the latest enforcement log for that user and returns a structured, human-readable explanation of why the decision was made. This is critical for audit compliance and transparency.

### Get Explanation for user "testuser" (user_id = 2)
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/explain/2/latest" | ConvertTo-Json -Depth 10
```

---

## Step 10: Check User Risk Scores

```powershell
# aadit's risk history
Invoke-RestMethod -Uri "http://127.0.0.1:5000/user/1/risk" | ConvertTo-Json -Depth 10
```

**Expected Output (key fields):**
```json
{
    "user_id": 1,
    "cumulative_risk": 100,
    "event_count": 7,
    "history": [
        { "risk_score": 52, "severity": "MEDIUM", "triggered_rules": "Brute Force, Behavioral Anomaly" },
        { "risk_score": 0, "severity": "LOW", "triggered_rules": "" },
        ...
    ]
}
```

```powershell
# testuser's risk history
Invoke-RestMethod -Uri "http://127.0.0.1:5000/user/2/risk" | ConvertTo-Json -Depth 10
```

**Expected:** `cumulative_risk: 55`, history showing Unknown Fingerprint and Velocity IP events.

**What's happening:** Module 5 (Risk Scoring) maintains a `risk_memory` table that accumulates risk across sessions. Each login event adds to the user's history in `threat_analysis`. This endpoint exposes both the current cumulative score and the last 20 login events.

---

## Step 11: Admin Dashboard (Browser)

Open your browser to this URL:

```
http://127.0.0.1:5000/admin?token=cortex-admin-2025
```

### Pages to Explore:

| Sidebar Link | URL | What You'll See |
|-------------|-----|-----------------|
| **Overview** | `/admin?token=cortex-admin-2025` | 6 metric cards (total users, logins, success/fail counts, active locks, avg risk), top 5 risk users table, recent enforcement actions |
| **Users** | `/admin/users?token=cortex-admin-2025` | All registered users with cumulative risk, severity badge, lock status, and total login count |
| **Logs** | `/admin/logs?token=cortex-admin-2025` | Paginated enforcement logs with severity/action dropdown filters |
| **Threats** | `/admin/threats?token=cortex-admin-2025` | Triggered rules summary (Brute Force, Velocity IP, etc.) with counts and total points. Top attacking IPs with an Unblock button |
| **System** | `/admin/system?token=cortex-admin-2025` | Database size (64 KB), total users/attempts/logs, threat feed count (15 entries), Refresh Feeds button, system info panel |

---

## Step 12: Admin API Endpoints

### Dashboard Stats
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/admin/stats" -Headers @{"X-Admin-Token"="cortex-admin-2025"} | ConvertTo-Json -Depth 10
```

### Enforcement Logs (Paginated)
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/admin/logs/data?page=1&per_page=5" -Headers @{"X-Admin-Token"="cortex-admin-2025"} | ConvertTo-Json -Depth 10
```

### User Risk Data
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/admin/users/data" -Headers @{"X-Admin-Token"="cortex-admin-2025"} | ConvertTo-Json -Depth 10
```

### Threat Map Data
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/admin/threats/data" -Headers @{"X-Admin-Token"="cortex-admin-2025"} | ConvertTo-Json -Depth 10
```

### System Health
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/admin/system/data" -Headers @{"X-Admin-Token"="cortex-admin-2025"} | ConvertTo-Json -Depth 10
```

### Refresh Threat Intelligence Feeds
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/admin/feeds/refresh" -Headers @{"X-Admin-Token"="cortex-admin-2025"} | ConvertTo-Json -Depth 10
```

**Expected:**
```json
{ "entries": 15, "refreshed": true, "timestamp": "2026-04-14 07:03:08" }
```

### Unblock an IP
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/admin/ip/unblock" -Method Post -Headers @{"X-Admin-Token"="cortex-admin-2025"} -ContentType "application/json" -Body '{"ip":"1.2.3.4"}'
```

---

## Step 13: Test Unauthorized Access (No Token)

```powershell
try {
    Invoke-RestMethod -Uri "http://127.0.0.1:5000/admin/stats"
} catch {
    Write-Host "Got 401 Unauthorized (expected!)"
    $_.ErrorDetails.Message
}
```

**Expected:** Returns the login page HTML (redirects to admin login). All `/admin/*` endpoints require the `X-Admin-Token` header or `?token=` query parameter.

---

## Quick Reference

| Item | Value |
|------|-------|
| **Admin Token** | `cortex-admin-2025` |
| **User 1** | username: `aadit`, password: `MyPass@123`, user_id: `1` |
| **User 2** | username: `testuser`, password: `Test@456`, user_id: `2` |
| **Server** | `http://127.0.0.1:5000` |
| **Dashboard** | `http://127.0.0.1:5000/admin?token=cortex-admin-2025` |

---

## How the 13-Module Pipeline Works

Every `POST /login` runs through this chain:

```
Request arrives
  │
  ├─► Module 6:  check_ip_lock()          → Is this IP blocked? If yes → 403
  ├─► Module 12: check_threat_intel()      → Is IP in known malicious ranges? (+35 risk)
  ├─► Module 2:  handle_login()            → Check username/password → SUCCESS or FAIL
  ├─► Module 6:  check_account_lock()      → Is this account locked? If yes → 403
  ├─► Module 11: build_fingerprint()       → SHA-256 hash of browser headers
  │              check_fingerprint()       → Is this a new device? (+15 risk)
  ├─► Module 3:  run_baseline_engine()     → Compare against known IPs, devices, hours
  ├─► Module 4:  run_rules()               → Check Brute Force, Unknown IP, New Device, Abnormal Time
  ├─► Module 9:  run_velocity_check()      → Too many attempts from this IP/user? (+25/+20)
  ├─► Module 10: check_impossible_travel() → GeoIP lookup → >500km in <60min? (+40)
  ├─► Module 5:  calculate_risk()          → Sum all risk points → severity (LOW/MEDIUM/HIGH)
  ├─► Module 6:  evaluate_lockdown()       → Score ≥40 = LOCK, ≥70 = LOCK + IP BLOCK
  ├─► Module 7:  apply_risk_decay()        → Clean login? Reduce cumulative risk by 10
  ├─► Module 13: generate_explanation()    → Create human-readable decision rationale
  └─► Module 8:  log_enforcement()         → Write everything to enforcement_logs table
```

---

## Risk Points Reference

| Rule | Points | What Triggers It |
|------|--------|------------------|
| Brute Force | +30 | 5+ failed logins in 5 minutes |
| Behavioral Anomaly | +20 | Login deviates from baseline (hours/IP/device) |
| Abnormal Login Time | +20 | Login outside user's typical hours |
| Unknown IP | +20 | IP not seen before for this user |
| New Device | +20 | User-Agent string not in user's baseline |
| Unknown Fingerprint | +15 | Browser fingerprint hash is new |
| Velocity IP | +25 | >10 attempts from same IP in 60 minutes |
| Velocity User | +20 | >8 attempts for same user in 60 minutes |
| Impossible Travel | +40 | >500km distance between logins in <60 minutes |
| Threat Intel Hit | +35 | IP matches known Tor exit node or botnet range |

## Enforcement Levels

| Cumulative Risk | Level | Action Taken |
|----------------|-------|--------------|
| 0 – 19 | 0 | **ALLOWED** — Login proceeds normally |
| 20 – 39 | 1 | **WARNED** — Login allowed with progressive delay warning |
| 40 – 69 | 2 | **LOCKED** — Account locked for 10 minutes |
| 70+ | 3 | **LOCKED + IP BLOCKED** — Account locked 30 min, IP blocked |

## Risk Decay (Module 7)

When a user logs in successfully with **zero rules triggered**, their cumulative risk is reduced by `DECAY_FACTOR = 10`. This rewards consistent normal behavior and prevents permanent lockouts from one-time anomalies.
