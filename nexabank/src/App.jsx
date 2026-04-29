import { useState, useEffect, useRef } from "react";

// ─── CORTEX API ───────────────────────────────────────────────────────────────
const CORTEX = "http://127.0.0.1:5000";

async function cortexRegister(username, password) {
  const res = await fetch(`${CORTEX}/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  return res.json();
}

async function cortexLogin(username, password, customUA) {
  const res = await fetch(`${CORTEX}/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(customUA ? { "User-Agent": customUA } : {}),
    },
    body: JSON.stringify({ username, password }),
  });
  const data = await res.json();
  return { ...data, httpStatus: res.status };
}

async function cortexDeleteUser(userId) {
  const res = await fetch(`${CORTEX}/user/${userId}/delete`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
  });
  return res.json();
}

// ─── MOCK BANK DATA ───────────────────────────────────────────────────────────
const MOCK_ACCOUNTS = [
  { id: "NX-4821", name: "Primary Checking", balance: 12480.5, type: "checking" },
  { id: "NX-9034", name: "Savings Vault", balance: 54200.0, type: "savings" },
  { id: "NX-2217", name: "Investment Fund", balance: 138750.25, type: "investment" },
];

const MOCK_TRANSACTIONS = [
  { id: 1, desc: "Netflix Subscription", amount: -15.99, date: "Apr 21", category: "Entertainment" },
  { id: 2, desc: "Salary Deposit", amount: 4200.0, date: "Apr 20", category: "Income" },
  { id: 3, desc: "Amazon Purchase", amount: -89.5, date: "Apr 19", category: "Shopping" },
  { id: 4, desc: "Electricity Bill", amount: -142.0, date: "Apr 18", category: "Utilities" },
  { id: 5, desc: "Restaurant Dinner", amount: -67.3, date: "Apr 17", category: "Food" },
  { id: 6, desc: "ATM Withdrawal", amount: -200.0, date: "Apr 16", category: "Cash" },
];

// ─── STYLES ───────────────────────────────────────────────────────────────────
const styles = `
  @import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Mono:wght@300;400;500&display=swap');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg: #080c10;
    --surface: #0e1419;
    --surface2: #141c24;
    --border: #1e2d3d;
    --accent: #00d4ff;
    --accent2: #00ff9d;
    --danger: #ff3b5c;
    --warn: #ffb830;
    --text: #e8f4f8;
    --muted: #4a6278;
    --font: 'Syne', sans-serif;
    --mono: 'DM Mono', monospace;
  }

  body { background: var(--bg); color: var(--text); font-family: var(--font); }

  .app { min-height: 100vh; display: flex; flex-direction: column; }

  /* ── NOISE OVERLAY ── */
  .app::before {
    content: '';
    position: fixed; inset: 0;
    background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)' opacity='0.04'/%3E%3C/svg%3E");
    pointer-events: none; z-index: 0; opacity: 0.4;
  }

  /* ── LOGIN ── */
  .login-wrap {
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: radial-gradient(ellipse 80% 60% at 50% 0%, #001a2e 0%, var(--bg) 70%);
    position: relative; overflow: hidden;
  }
  .login-glow {
    position: absolute; width: 600px; height: 600px; border-radius: 50%;
    background: radial-gradient(circle, rgba(0,212,255,0.06) 0%, transparent 70%);
    top: -200px; left: 50%; transform: translateX(-50%);
    pointer-events: none;
  }
  .login-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 48px 44px;
    width: 100%; max-width: 440px;
    position: relative; z-index: 1;
    box-shadow: 0 40px 80px rgba(0,0,0,0.6), 0 0 0 1px rgba(0,212,255,0.05);
  }
  .login-logo {
    display: flex; align-items: center; gap: 10px;
    margin-bottom: 32px;
  }
  .logo-icon {
    width: 38px; height: 38px; background: linear-gradient(135deg, var(--accent), var(--accent2));
    border-radius: 10px; display: flex; align-items: center; justify-content: center;
    font-size: 18px; font-weight: 800; color: #000;
  }
  .logo-text { font-size: 22px; font-weight: 800; letter-spacing: -0.5px; }
  .logo-sub { font-size: 11px; color: var(--muted); letter-spacing: 3px; text-transform: uppercase; font-family: var(--mono); }
  .login-title { font-size: 28px; font-weight: 700; margin-bottom: 6px; }
  .login-sub { color: var(--muted); font-size: 14px; margin-bottom: 32px; font-family: var(--mono); }

  .field { margin-bottom: 18px; }
  .field label { display: block; font-size: 11px; letter-spacing: 2px; text-transform: uppercase; color: var(--muted); margin-bottom: 8px; font-family: var(--mono); }
  .field input, .field select {
    width: 100%; padding: 14px 16px;
    background: var(--surface2); border: 1px solid var(--border);
    border-radius: 10px; color: var(--text); font-family: var(--mono); font-size: 14px;
    outline: none; transition: border-color 0.2s, box-shadow 0.2s;
  }
  .field input:focus, .field select:focus {
    border-color: var(--accent); box-shadow: 0 0 0 3px rgba(0,212,255,0.08);
  }
  .field select option { background: var(--surface2); }

  .btn {
    width: 100%; padding: 15px; border: none; border-radius: 10px; cursor: pointer;
    font-family: var(--font); font-size: 15px; font-weight: 700; letter-spacing: 0.5px;
    transition: all 0.2s; position: relative; overflow: hidden;
  }
  .btn-primary {
    background: linear-gradient(135deg, var(--accent) 0%, #0099cc 100%);
    color: #000;
  }
  .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 8px 24px rgba(0,212,255,0.3); }
  .btn-primary:active { transform: translateY(0); }
  .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }

  .btn-ghost {
    background: transparent; border: 1px solid var(--border); color: var(--muted);
    margin-top: 10px;
  }
  .btn-ghost:hover { border-color: var(--accent); color: var(--accent); }

  .btn-danger {
    background: linear-gradient(135deg, var(--danger), #cc1133);
    color: #fff; margin-top: 8px;
  }
  .btn-danger:hover { box-shadow: 0 8px 24px rgba(255,59,92,0.3); transform: translateY(-1px); }

  /* ── CORTEX PANEL ── */
  .cortex-panel {
    margin-top: 20px; padding: 16px;
    border-radius: 12px; font-family: var(--mono); font-size: 12px;
    border: 1px solid; transition: all 0.3s;
  }
  .cortex-panel.allowed { background: rgba(0,255,157,0.05); border-color: rgba(0,255,157,0.2); }
  .cortex-panel.locked  { background: rgba(255,59,92,0.08); border-color: rgba(255,59,92,0.3); }
  .cortex-panel.warned  { background: rgba(255,184,48,0.06); border-color: rgba(255,184,48,0.25); }
  .cortex-panel.error   { background: rgba(255,59,92,0.06); border-color: rgba(255,59,92,0.2); }

  .cortex-header { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
  .cortex-badge {
    padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; letter-spacing: 1px;
  }
  .badge-allowed { background: rgba(0,255,157,0.15); color: var(--accent2); }
  .badge-locked  { background: rgba(255,59,92,0.15); color: var(--danger); }
  .badge-warned  { background: rgba(255,184,48,0.15); color: var(--warn); }
  .badge-error   { background: rgba(255,59,92,0.1); color: var(--danger); }

  .cortex-row { display: flex; justify-content: space-between; padding: 3px 0; color: var(--muted); }
  .cortex-val { color: var(--text); }
  .cortex-rules { margin-top: 8px; }
  .cortex-rule-tag {
    display: inline-block; padding: 2px 8px; background: rgba(255,59,92,0.1);
    color: var(--danger); border-radius: 4px; font-size: 10px; margin: 2px;
  }

  /* ── ATTACK PANEL ── */
  .attack-panel {
    margin-top: 20px; padding: 16px;
    background: rgba(255,59,92,0.04); border: 1px solid rgba(255,59,92,0.15);
    border-radius: 12px;
  }
  .attack-title { font-size: 11px; letter-spacing: 2px; color: var(--danger); text-transform: uppercase; font-family: var(--mono); margin-bottom: 12px; }
  .attack-btn {
    width: 100%; padding: 10px 14px; margin-bottom: 8px;
    background: var(--surface2); border: 1px solid var(--border);
    border-radius: 8px; color: var(--text); font-family: var(--mono); font-size: 12px;
    cursor: pointer; text-align: left; transition: all 0.2s;
  }
  .attack-btn:hover { border-color: var(--danger); color: var(--danger); background: rgba(255,59,92,0.05); }
  .attack-label { font-size: 10px; color: var(--muted); display: block; margin-top: 2px; }

  /* ── DASHBOARD ── */
  .dashboard { display: flex; min-height: 100vh; }

  .sidebar {
    width: 240px; min-height: 100vh;
    background: var(--surface); border-right: 1px solid var(--border);
    padding: 28px 20px; display: flex; flex-direction: column; flex-shrink: 0;
  }
  .sidebar-logo { display: flex; align-items: center; gap: 10px; margin-bottom: 36px; padding-bottom: 24px; border-bottom: 1px solid var(--border); }
  .nav-section { font-size: 10px; letter-spacing: 2px; color: var(--muted); text-transform: uppercase; font-family: var(--mono); margin: 20px 0 8px; }
  .nav-item {
    display: flex; align-items: center; gap: 10px; padding: 10px 12px;
    border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 600;
    color: var(--muted); transition: all 0.15s; margin-bottom: 2px; border: none;
    background: none; width: 100%; text-align: left;
  }
  .nav-item:hover { background: var(--surface2); color: var(--text); }
  .nav-item.active { background: rgba(0,212,255,0.08); color: var(--accent); }
  .nav-item .icon { font-size: 16px; width: 20px; }

  .sidebar-footer { margin-top: auto; padding-top: 20px; border-top: 1px solid var(--border); }
  .user-chip { display: flex; align-items: center; gap: 10px; }
  .user-avatar {
    width: 34px; height: 34px; border-radius: 8px;
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    display: flex; align-items: center; justify-content: center;
    font-weight: 800; font-size: 13px; color: #000; flex-shrink: 0;
  }
  .user-name { font-size: 13px; font-weight: 600; }
  .user-id { font-size: 11px; color: var(--muted); font-family: var(--mono); }

  /* ── MAIN ── */
  .main { flex: 1; overflow-y: auto; }
  .topbar {
    padding: 20px 32px; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
    background: var(--surface); position: sticky; top: 0; z-index: 10;
  }
  .topbar-title { font-size: 20px; font-weight: 700; }
  .cortex-live {
    display: flex; align-items: center; gap: 8px;
    font-family: var(--mono); font-size: 12px; color: var(--muted);
  }
  .live-dot {
    width: 7px; height: 7px; border-radius: 50%; background: var(--accent2);
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.5; transform: scale(0.8); }
  }

  .content { padding: 32px; }

  /* ── CARDS ── */
  .cards-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 16px; margin-bottom: 32px; }
  .account-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 16px; padding: 24px; cursor: pointer;
    transition: all 0.2s; position: relative; overflow: hidden;
  }
  .account-card::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, var(--accent), var(--accent2));
    opacity: 0; transition: opacity 0.2s;
  }
  .account-card:hover { border-color: rgba(0,212,255,0.3); transform: translateY(-2px); }
  .account-card:hover::before { opacity: 1; }
  .account-card.savings::before { background: linear-gradient(90deg, var(--accent2), #00cc88); }
  .account-card.investment::before { background: linear-gradient(90deg, var(--warn), #ff8800); }

  .card-type { font-size: 10px; letter-spacing: 2px; text-transform: uppercase; color: var(--muted); font-family: var(--mono); margin-bottom: 16px; }
  .card-balance { font-size: 32px; font-weight: 800; letter-spacing: -1px; margin-bottom: 4px; }
  .card-name { font-size: 13px; color: var(--muted); }
  .card-id { font-size: 11px; color: var(--muted); font-family: var(--mono); margin-top: 12px; }

  /* ── RISK WIDGET ── */
  .risk-widget {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 16px; padding: 24px; margin-bottom: 24px;
  }
  .risk-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
  .risk-title { font-size: 13px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; font-family: var(--mono); color: var(--muted); }
  .risk-score-big { font-size: 48px; font-weight: 800; letter-spacing: -2px; }
  .risk-score-big.low { color: var(--accent2); }
  .risk-score-big.medium { color: var(--warn); }
  .risk-score-big.high { color: var(--danger); }
  .risk-bar-wrap { height: 6px; background: var(--surface2); border-radius: 3px; overflow: hidden; margin-top: 12px; }
  .risk-bar { height: 100%; border-radius: 3px; transition: width 0.5s ease; }
  .risk-bar.low { background: linear-gradient(90deg, var(--accent2), var(--accent)); }
  .risk-bar.medium { background: linear-gradient(90deg, var(--warn), #ff6600); }
  .risk-bar.high { background: linear-gradient(90deg, var(--danger), #cc0022); }

  /* ── TRANSACTIONS ── */
  .section-title { font-size: 16px; font-weight: 700; margin-bottom: 16px; }
  .tx-list { background: var(--surface); border: 1px solid var(--border); border-radius: 16px; overflow: hidden; }
  .tx-item {
    display: flex; align-items: center; justify-content: space-between;
    padding: 16px 20px; border-bottom: 1px solid var(--border); transition: background 0.15s;
  }
  .tx-item:last-child { border-bottom: none; }
  .tx-item:hover { background: var(--surface2); }
  .tx-left { display: flex; align-items: center; gap: 14px; }
  .tx-icon {
    width: 38px; height: 38px; border-radius: 10px; background: var(--surface2);
    display: flex; align-items: center; justify-content: center; font-size: 16px; flex-shrink: 0;
  }
  .tx-desc { font-size: 14px; font-weight: 600; }
  .tx-meta { font-size: 12px; color: var(--muted); font-family: var(--mono); margin-top: 2px; }
  .tx-amount { font-size: 15px; font-weight: 700; font-family: var(--mono); }
  .tx-amount.credit { color: var(--accent2); }
  .tx-amount.debit { color: var(--text); }

  /* ── TRANSFER ── */
  .transfer-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 16px; padding: 28px; max-width: 480px;
  }
  .transfer-success {
    text-align: center; padding: 32px;
    background: rgba(0,255,157,0.05); border: 1px solid rgba(0,255,157,0.2);
    border-radius: 16px;
  }

  /* ── ATTACK LAB ── */
  .attack-lab {
    background: var(--surface); border: 1px solid rgba(255,59,92,0.2);
    border-radius: 16px; padding: 28px;
  }
  .attack-lab-title { font-size: 18px; font-weight: 700; margin-bottom: 6px; }
  .attack-lab-sub { color: var(--muted); font-size: 13px; font-family: var(--mono); margin-bottom: 28px; }
  .attack-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 16px; }
  .attack-card {
    background: var(--surface2); border: 1px solid var(--border);
    border-radius: 12px; padding: 20px; cursor: pointer; transition: all 0.2s;
  }
  .attack-card:hover { border-color: var(--danger); transform: translateY(-2px); box-shadow: 0 8px 24px rgba(255,59,92,0.1); }
  .attack-card-icon { font-size: 28px; margin-bottom: 12px; }
  .attack-card-name { font-size: 14px; font-weight: 700; margin-bottom: 4px; }
  .attack-card-desc { font-size: 12px; color: var(--muted); font-family: var(--mono); line-height: 1.5; }
  .attack-card-tag {
    display: inline-block; margin-top: 10px; padding: 3px 8px;
    background: rgba(255,59,92,0.1); color: var(--danger);
    border-radius: 4px; font-size: 10px; font-family: var(--mono); letter-spacing: 1px;
  }
  .attack-running { margin-top: 24px; }
  .attack-log {
    background: #050810; border: 1px solid var(--border); border-radius: 10px;
    padding: 16px; font-family: var(--mono); font-size: 12px;
    max-height: 280px; overflow-y: auto; margin-top: 12px;
  }
  .log-line { padding: 3px 0; border-bottom: 1px solid rgba(255,255,255,0.03); }
  .log-line.ok { color: var(--accent2); }
  .log-line.bad { color: var(--danger); }
  .log-line.warn { color: var(--warn); }
  .log-line.info { color: var(--muted); }

  .progress-wrap { height: 4px; background: var(--surface2); border-radius: 2px; margin-top: 12px; }
  .progress-bar {
    height: 100%; background: linear-gradient(90deg, var(--accent), var(--accent2));
    border-radius: 2px; transition: width 0.3s;
  }

  .tag-row { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
  .tag { padding: 3px 10px; border-radius: 20px; font-size: 11px; font-family: var(--mono); }
  .tag-blue { background: rgba(0,212,255,0.1); color: var(--accent); }
  .tag-green { background: rgba(0,255,157,0.1); color: var(--accent2); }
  .tag-red { background: rgba(255,59,92,0.1); color: var(--danger); }

  /* ── LOGOUT BTN ── */
  .logout-btn {
    background: none; border: none; color: var(--muted); cursor: pointer;
    font-family: var(--mono); font-size: 12px; padding: 8px 12px;
    border-radius: 6px; transition: all 0.15s; display: flex; align-items: center; gap: 6px;
  }
  .logout-btn:hover { color: var(--danger); background: rgba(255,59,92,0.08); }

  /* ── SPINNER ── */
  .spinner {
    width: 16px; height: 16px; border: 2px solid rgba(0,0,0,0.2);
    border-top-color: #000; border-radius: 50%;
    animation: spin 0.6s linear infinite; display: inline-block;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  .error-msg { color: var(--danger); font-size: 12px; font-family: var(--mono); margin-top: 10px; text-align: center; }
  .divider { height: 1px; background: var(--border); margin: 20px 0; }
`;

const CATEGORY_ICONS = {
  Entertainment: "🎬", Income: "💰", Shopping: "🛍️",
  Utilities: "⚡", Food: "🍽️", Cash: "💵",
};

// ─── COMPONENT ────────────────────────────────────────────────────────────────
export default function NexaBank() {
  const [page, setPage] = useState("login"); // login | register | dashboard
  const [activeTab, setActiveTab] = useState("overview");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [cortexResult, setCortexResult] = useState(null);
  const [currentUser, setCurrentUser] = useState(null);
  const [failedAttempts, setFailedAttempts] = useState(0);
  const [cooldown, setCooldown] = useState(0);
  const cooldownRef = useRef(null);
  const [transferAmt, setTransferAmt] = useState("");
  const [transferTo, setTransferTo] = useState("");
  const [transferDone, setTransferDone] = useState(false);
  const [attackLogs, setAttackLogs] = useState([]);
  const [attackRunning, setAttackRunning] = useState(false);
  const [attackProgress, setAttackProgress] = useState(0);
  const [activeAttack, setActiveAttack] = useState(null);
  const logRef = useRef(null);
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState(false);

  useEffect(() => {
    const s = document.createElement("style");
    s.textContent = styles;
    document.head.appendChild(s);
    return () => document.head.removeChild(s);
  }, []);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [attackLogs]);

  function addLog(msg, type = "info") {
    const ts = new Date().toLocaleTimeString();
    setAttackLogs(l => [...l, { msg: `[${ts}] ${msg}`, type }]);
  }

  // ── REGISTER ──
  async function handleRegister() {
    if (!username || !password) return setError("Fill in all fields.");
    setLoading(true); setError(""); setCortexResult(null);
    try {
      const res = await cortexRegister(username, password);
      if (res.status === "REGISTERED") {
        setError(""); setPage("login");
        setCortexResult({ type: "allowed", msg: "Account created! You can now log in." });
      } else {
        setError(res.message || res.error || "Registration failed.");
      }
    } catch {
      setError("Cannot connect to CORTEX backend. Is it running?");
    }
    setLoading(false);
  }

  // ── LOGIN ──
  async function handleLogin() {
    if (!username || !password) return setError("Fill in all fields.");
    if (cooldown > 0) return setError(`Too many failed attempts. Wait ${cooldown}s before retrying.`);
    setLoading(true); setError(""); setCortexResult(null);
    try {
      const res = await cortexLogin(username, password);
      const status = res.status?.toUpperCase();
      const action = res.enforcement_action?.toUpperCase();

      if (status === "SUCCESS" && (action === "ALLOWED" || action === "WARNED")) {
        setFailedAttempts(0); setCooldown(0);
        if (cooldownRef.current) clearInterval(cooldownRef.current);
        setCurrentUser({ username, userId: res.user_id, riskScore: res.risk_score, severity: res.severity?.toLowerCase() });
        if (action === "WARNED") {
          setCortexResult({ type: "warned", res });
          setTimeout(() => { setCortexResult(null); setPage("dashboard"); }, 2500);
        } else {
          setPage("dashboard");
        }
      } else if (status === "LOCKED" || res.httpStatus === 403) {
        setPassword("");
        setFailedAttempts(0);
        setCortexResult({ type: "locked", res });
      } else {
        setPassword("");
        const newAttempts = failedAttempts + 1;
        setFailedAttempts(newAttempts);
        const waitSec = newAttempts >= 3 ? 10 : newAttempts * 3;
        setCooldown(waitSec);
        setError(`Invalid credentials. Wait ${waitSec}s before retrying. (Attempt ${newAttempts})`);
        if (cooldownRef.current) clearInterval(cooldownRef.current);
        cooldownRef.current = setInterval(() => {
          setCooldown(prev => {
            if (prev <= 1) { clearInterval(cooldownRef.current); setError(""); return 0; }
            return prev - 1;
          });
        }, 1000);
      }
    } catch {
      setError("Cannot connect to CORTEX backend at 127.0.0.1:5000. Make sure it's running.");
    }
    setLoading(false);
  }

  // ── ATTACK SIMULATIONS ──
  const attacks = [
    {
      id: "brute",
      icon: "🔨",
      name: "Brute Force Attack",
      desc: "Sends 8 rapid login attempts with wrong passwords to trigger velocity detection and account lockdown.",
      tag: "VELOCITY · LOCKDOWN",
      run: async () => {
        addLog("Starting brute force — 8 attempts with bad passwords...", "warn");
        for (let i = 1; i <= 8; i++) {
          addLog(`Attempt ${i}/8 → password: 'hack${i}'`, "info");
          try {
            const r = await cortexLogin(username || "testuser", `hack${i}`);
            const action = r.enforcement_action || r.status;
            if (r.status === "locked" || action === "LOCKED") {
              addLog(`✖ LOCKED after attempt ${i}! Risk: ${r.risk_score} | ${r.severity}`, "bad");
              addLog("CORTEX triggered: Account Lockdown ✓", "ok");
              setAttackProgress(100); break;
            } else {
              addLog(`  → ${action || r.status} | Risk: ${r.risk_score ?? 0}`, r.risk_score > 0 ? "warn" : "info");
            }
          } catch { addLog("  → Connection error", "bad"); }
          setAttackProgress(Math.round((i / 8) * 100));
          await new Promise(r => setTimeout(r, 400));
        }
        addLog("Brute force complete.", "ok");
      }
    },
    {
      id: "sqli",
      icon: "💉",
      name: "SQL Injection",
      desc: "Tries classic SQLi payloads in the username field to attempt authentication bypass.",
      tag: "AUTH BYPASS",
      run: async () => {
        const payloads = ["' OR '1'='1", "admin'--", "' OR 1=1--", "'; DROP TABLE users;--", "' UNION SELECT 1,2,3--"];
        addLog("Injecting SQL payloads into username field...", "warn");
        for (let i = 0; i < payloads.length; i++) {
          addLog(`Payload: ${payloads[i]}`, "info");
          try {
            const r = await cortexLogin(payloads[i], "password");
            addLog(`  → ${r.status} | Risk: ${r.risk_score ?? 0}`, "ok");
          } catch { addLog("  → Error", "bad"); }
          setAttackProgress(Math.round(((i + 1) / payloads.length) * 100));
          await new Promise(r => setTimeout(r, 500));
        }
        addLog("SQLi test complete. CORTEX should flag anomalous usernames.", "ok");
      }
    },
    {
      id: "xss",
      icon: "📜",
      name: "XSS Injection",
      desc: "Submits XSS payloads as credentials to test input handling and anomaly detection.",
      tag: "INPUT ANOMALY",
      run: async () => {
        const payloads = [
          "<script>alert('xss')</script>",
          "<img src=x onerror=alert(1)>",
          "javascript:alert(1)",
          "<svg onload=alert(1)>",
        ];
        addLog("Sending XSS payloads as login credentials...", "warn");
        for (let i = 0; i < payloads.length; i++) {
          addLog(`Payload: ${payloads[i].substring(0, 40)}...`, "info");
          try {
            const r = await cortexLogin(payloads[i], "x");
            addLog(`  → ${r.status} | Risk: ${r.risk_score ?? 0}`, "ok");
          } catch { addLog("  → Error", "bad"); }
          setAttackProgress(Math.round(((i + 1) / payloads.length) * 100));
          await new Promise(r => setTimeout(r, 450));
        }
        addLog("XSS test complete.", "ok");
      }
    },
    {
      id: "device",
      icon: "📱",
      name: "New Device Fingerprint",
      desc: "Logs in with different User-Agent strings to simulate logins from multiple unknown devices.",
      tag: "SESSION FINGERPRINT",
      run: async () => {
        const agents = [
          "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)",
          "Mozilla/5.0 (Linux; Android 14) Chrome/120",
          "curl/7.85.0",
          "python-requests/2.31.0",
          "Mozilla/5.0 (compatible; Googlebot/2.1)",
        ];
        addLog(`Testing with ${agents.length} different device fingerprints...`, "warn");
        for (let i = 0; i < agents.length; i++) {
          addLog(`Device ${i + 1}: ${agents[i].substring(0, 45)}`, "info");
          try {
            const r = await cortexLogin(username || "testuser", password || "testpass123", agents[i]);
            addLog(`  → ${r.enforcement_action || r.status} | Risk: ${r.risk_score ?? 0} | Rules: ${r.triggered_rules?.length ?? 0}`, r.risk_score > 0 ? "warn" : "ok");
          } catch { addLog("  → Error", "bad"); }
          setAttackProgress(Math.round(((i + 1) / agents.length) * 100));
          await new Promise(r => setTimeout(r, 600));
        }
        addLog("Fingerprint test complete. Check CORTEX dashboard for flagged devices.", "ok");
      }
    },
    {
      id: "takeover",
      icon: "👤",
      name: "Account Takeover Sim",
      desc: "Combines failed logins + new device + rapid attempts to simulate a full account takeover attack chain.",
      tag: "MULTI-VECTOR",
      run: async () => {
        addLog("Starting account takeover simulation (multi-vector)...", "warn");
        addLog("Phase 1: Credential stuffing (3 bad passwords)...", "info");
        for (let i = 1; i <= 3; i++) {
          try {
            const r = await cortexLogin(username || "testuser", `stuffed${i}`);
            addLog(`  Attempt ${i} → ${r.status} | Risk: ${r.risk_score ?? 0}`, "info");
          } catch {}
          setAttackProgress(Math.round((i / 10) * 100));
          await new Promise(r => setTimeout(r, 400));
        }
        addLog("Phase 2: Switching to unknown device...", "warn");
        try {
          const r = await cortexLogin(username || "testuser", password || "testpass123", "python-requests/2.28.0");
          addLog(`  Unknown device login → ${r.enforcement_action || r.status} | Risk: ${r.risk_score}`, r.risk_score > 20 ? "bad" : "warn");
        } catch {}
        setAttackProgress(60);
        await new Promise(r => setTimeout(r, 500));
        addLog("Phase 3: Rapid re-attempts...", "warn");
        for (let i = 1; i <= 4; i++) {
          try {
            const r = await cortexLogin(username || "testuser", `rapid${i}`);
            if (r.status === "locked") {
              addLog(`✖ ACCOUNT LOCKED — CORTEX stopped the takeover! ✓`, "bad");
              setAttackProgress(100); break;
            }
            addLog(`  Rapid ${i} → ${r.status} | Risk: ${r.risk_score ?? 0}`, "warn");
          } catch {}
          setAttackProgress(60 + Math.round((i / 4) * 40));
          await new Promise(r => setTimeout(r, 350));
        }
        addLog("Takeover simulation complete. Open CORTEX dashboard to review.", "ok");
      }
    },
    {
      id: "replay",
      icon: "🔁",
      name: "Credential Replay",
      desc: "Sends the same valid credentials 10 times rapidly to test velocity and session anomaly detection.",
      tag: "VELOCITY",
      run: async () => {
        addLog(`Replaying credentials for '${username || "testuser"}' 10 times rapidly...`, "warn");
        for (let i = 1; i <= 10; i++) {
          try {
            const r = await cortexLogin(username || "testuser", password || "testpass123");
            addLog(`  #${i} → ${r.enforcement_action || r.status} | Risk: ${r.risk_score ?? 0} | Rules: ${JSON.stringify(r.triggered_rules?.map(t => t.rule_name) ?? [])}`, r.risk_score > 20 ? "warn" : "ok");
          } catch { addLog(`  #${i} → Error`, "bad"); }
          setAttackProgress(Math.round((i / 10) * 100));
          await new Promise(r => setTimeout(r, 200));
        }
        addLog("Replay attack complete.", "ok");
      }
    },
  ];

  async function runAttack(attack) {
    if (attackRunning) return;
    setActiveAttack(attack.id);
    setAttackLogs([]);
    setAttackProgress(0);
    setAttackRunning(true);
    await attack.run();
    setAttackRunning(false);
  }

  // ── DELETE PROFILE ──
  async function handleDeleteProfile() {
    if (!deleteConfirm) { setDeleteConfirm(true); return; }
    setDeleteLoading(true);
    try {
      const res = await cortexDeleteUser(currentUser.userId);
      if (res.status === "deleted") {
        setPage("login"); setCurrentUser(null); setUsername(""); setPassword("");
        setCortexResult({ type: "allowed", msg: "Your profile has been permanently deleted." });
      } else {
        setError(res.error || "Failed to delete profile.");
      }
    } catch {
      setError("Cannot connect to CORTEX backend.");
    }
    setDeleteLoading(false); setDeleteConfirm(false);
  }

  // ── SEVERITY HELPERS ──
  function sevClass(s) {
    const v = (s || "low").toLowerCase();
    if (v === "high" || v === "critical") return "high";
    if (v === "medium") return "medium";
    return "low";
  }

  // ── RENDER: LOGIN ──
  function renderLogin() {
    return (
      <div className="login-wrap">
        <div className="login-glow" />
        <div className="login-card">
          <div className="login-logo">
            <div className="logo-icon">N</div>
            <div>
              <div className="logo-text">NexaBank</div>
              <div className="logo-sub">Secured by CORTEX</div>
            </div>
          </div>
          <div className="login-title">Welcome back</div>
          <div className="login-sub">$ authenticate to continue_</div>

          <div className="field">
            <label>Username</label>
            <input value={username} onChange={e => setUsername(e.target.value)} placeholder="your_username" onKeyDown={e => e.key === "Enter" && handleLogin()} />
          </div>
          <div className="field">
            <label>Password</label>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••" onKeyDown={e => e.key === "Enter" && handleLogin()} />
          </div>

          {error && <div className="error-msg">{error}</div>}

          <button className="btn btn-primary" onClick={handleLogin} disabled={loading} style={{ marginTop: 8 }}>
            {loading ? <span className="spinner" /> : cooldown > 0 ? `Wait ${cooldown}s...` : "Sign In"}
          </button>
          <button className="btn btn-ghost" onClick={() => { setPage("register"); setError(""); setCortexResult(null); }}>
            Create Account
          </button>

          {cortexResult && (
            <div className={`cortex-panel ${cortexResult.type}`}>
              <div className="cortex-header">
                <span style={{ fontSize: 12, color: "var(--muted)", fontFamily: "var(--mono)" }}>CORTEX</span>
                <span className={`cortex-badge badge-${cortexResult.type}`}>
                  {cortexResult.type.toUpperCase()}
                </span>
              </div>
              {cortexResult.msg && <div style={{ fontSize: 12, color: "var(--text)" }}>{cortexResult.msg}</div>}
              {cortexResult.res && (
                <>
                  <div className="cortex-row"><span>Risk Score</span><span className="cortex-val">{cortexResult.res.risk_score ?? 0}</span></div>
                  <div className="cortex-row"><span>Severity</span><span className="cortex-val">{cortexResult.res.severity}</span></div>
                  <div className="cortex-row"><span>Action</span><span className="cortex-val">{cortexResult.res.enforcement_action || cortexResult.res.status}</span></div>
                  {cortexResult.res.explanation?.reason_summary && (
                    <div style={{ marginTop: 8, fontSize: 11, color: "var(--muted)", lineHeight: 1.5 }}>
                      {cortexResult.res.explanation.reason_summary}
                    </div>
                  )}
                  {cortexResult.res.triggered_rules?.length > 0 && (
                    <div className="cortex-rules">
                      {cortexResult.res.triggered_rules.map((r, i) => (
                        <span key={i} className="cortex-rule-tag">{r.rule_name}</span>
                      ))}
                    </div>
                  )}
                </>
              )}
            </div>
          )}

          <div className="divider" />
          <div className="attack-panel">
            <div className="attack-title">⚡ Quick Attack Tests</div>
            <button className="attack-btn" onClick={async () => {
              setError(""); setCortexResult(null);
              for (let i = 0; i < 6; i++) {
                await cortexLogin(username || "testuser", `wrong${i}`).catch(() => {});
                await new Promise(r => setTimeout(r, 300));
              }
              const r = await cortexLogin(username || "testuser", `wrong_final`).catch(() => ({}));
              setCortexResult({ type: r.status === "locked" ? "locked" : "warned", res: r });
            }}>
              🔨 Brute Force (6 attempts)
              <span className="attack-label">Triggers velocity detection + lockdown</span>
            </button>
            <button className="attack-btn" onClick={async () => {
              setError(""); setCortexResult(null);
              const r = await cortexLogin("' OR '1'='1", "x").catch(() => ({}));
              setCortexResult({ type: "allowed", res: r, msg: `SQLi attempt → ${r.status}` });
            }}>
              💉 SQL Injection Payload
              <span className="attack-label">Injects ' OR '1'='1 into username</span>
            </button>
          </div>
        </div>
      </div>
    );
  }

  // ── RENDER: REGISTER ──
  function renderRegister() {
    return (
      <div className="login-wrap">
        <div className="login-glow" />
        <div className="login-card">
          <div className="login-logo">
            <div className="logo-icon">N</div>
            <div>
              <div className="logo-text">NexaBank</div>
              <div className="logo-sub">Secured by CORTEX</div>
            </div>
          </div>
          <div className="login-title">Open an Account</div>
          <div className="login-sub">$ register new_user_</div>
          <div className="field">
            <label>Username</label>
            <input value={username} onChange={e => setUsername(e.target.value)} placeholder="choose_username" />
          </div>
          <div className="field">
            <label>Password</label>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••" />
          </div>
          {error && <div className="error-msg">{error}</div>}
          {cortexResult && <div className="cortex-panel allowed"><div style={{ fontSize: 13 }}>{cortexResult.msg}</div></div>}
          <button className="btn btn-primary" onClick={handleRegister} disabled={loading} style={{ marginTop: 8 }}>
            {loading ? <span className="spinner" /> : "Create Account"}
          </button>
          <button className="btn btn-ghost" onClick={() => { setPage("login"); setError(""); setCortexResult(null); }}>
            Back to Sign In
          </button>
        </div>
      </div>
    );
  }

  // ── RENDER: DASHBOARD ──
  function renderDashboard() {
    const sev = sevClass(currentUser?.severity);
    const totalBalance = MOCK_ACCOUNTS.reduce((s, a) => s + a.balance, 0);

    return (
      <div className="dashboard">
        <div className="sidebar">
          <div className="sidebar-logo">
            <div className="logo-icon">N</div>
            <div>
              <div className="logo-text" style={{ fontSize: 18 }}>NexaBank</div>
              <div className="logo-sub" style={{ fontSize: 9 }}>Secured by CORTEX</div>
            </div>
          </div>

          <div className="nav-section">Banking</div>
          {[
            { id: "overview", icon: "◈", label: "Overview" },
            { id: "accounts", icon: "▣", label: "Accounts" },
            { id: "transactions", icon: "↕", label: "Transactions" },
            { id: "transfer", icon: "→", label: "Transfer" },
          ].map(n => (
            <button key={n.id} className={`nav-item ${activeTab === n.id ? "active" : ""}`} onClick={() => setActiveTab(n.id)}>
              <span className="icon">{n.icon}</span>{n.label}
            </button>
          ))}

          <div className="nav-section">Security</div>
          <button className={`nav-item ${activeTab === "attacklab" ? "active" : ""}`} onClick={() => setActiveTab("attacklab")}>
            <span className="icon">⚡</span>Attack Lab
          </button>

          <div className="nav-section">Account</div>
          <button className={`nav-item ${activeTab === "profile" ? "active" : ""}`} onClick={() => { setActiveTab("profile"); setDeleteConfirm(false); }}>
            <span className="icon">⊕</span>Profile
          </button>

          <div className="sidebar-footer">
            <div className="user-chip">
              <div className="user-avatar">{currentUser?.username?.[0]?.toUpperCase()}</div>
              <div>
                <div className="user-name">{currentUser?.username}</div>
                <div className="user-id">ID #{currentUser?.userId}</div>
              </div>
            </div>
            <button className="logout-btn" style={{ marginTop: 12, width: "100%" }} onClick={() => { setPage("login"); setCurrentUser(null); setUsername(""); setPassword(""); }}>
              ⏻ Sign Out
            </button>
          </div>
        </div>

        <div className="main">
          <div className="topbar">
            <div className="topbar-title">
              {activeTab === "overview" && "Overview"}
              {activeTab === "accounts" && "Accounts"}
              {activeTab === "transactions" && "Transactions"}
              {activeTab === "transfer" && "Transfer Funds"}
              {activeTab === "attacklab" && "Attack Lab"}
              {activeTab === "profile" && "My Profile"}
            </div>
            <div className="cortex-live">
              <div className="live-dot" />
              CORTEX LIVE · Risk: <span style={{ color: sev === "high" ? "var(--danger)" : sev === "medium" ? "var(--warn)" : "var(--accent2)", marginLeft: 4, fontWeight: 700 }}>{currentUser?.riskScore ?? 0}</span>
            </div>
          </div>

          <div className="content">
            {/* OVERVIEW */}
            {activeTab === "overview" && (
              <>
                <div className="risk-widget">
                  <div className="risk-header">
                    <div className="risk-title">CORTEX Risk Profile</div>
                    <div className="tag-row">
                      <span className={`tag tag-${sev === "high" ? "red" : sev === "medium" ? "blue" : "green"}`}>{(currentUser?.severity || "low").toUpperCase()}</span>
                      <span className="tag tag-blue">SESSION ACTIVE</span>
                    </div>
                  </div>
                  <div className={`risk-score-big ${sev}`}>{currentUser?.riskScore ?? 0}</div>
                  <div style={{ fontSize: 12, color: "var(--muted)", fontFamily: "var(--mono)", marginTop: 4 }}>cumulative risk score</div>
                  <div className="risk-bar-wrap">
                    <div className={`risk-bar ${sev}`} style={{ width: `${Math.min((currentUser?.riskScore ?? 0), 100)}%` }} />
                  </div>
                </div>

                <div style={{ marginBottom: 16, fontSize: 13, color: "var(--muted)", fontFamily: "var(--mono)" }}>
                  Total Balance: <span style={{ color: "var(--accent2)", fontWeight: 700, fontSize: 20 }}>${totalBalance.toLocaleString("en-US", { minimumFractionDigits: 2 })}</span>
                </div>

                <div className="cards-grid">
                  {MOCK_ACCOUNTS.map(acc => (
                    <div key={acc.id} className={`account-card ${acc.type}`}>
                      <div className="card-type">{acc.type}</div>
                      <div className="card-balance">${acc.balance.toLocaleString("en-US", { minimumFractionDigits: 2 })}</div>
                      <div className="card-name">{acc.name}</div>
                      <div className="card-id">{acc.id}</div>
                    </div>
                  ))}
                </div>

                <div className="section-title">Recent Activity</div>
                <div className="tx-list">
                  {MOCK_TRANSACTIONS.slice(0, 4).map(tx => (
                    <div key={tx.id} className="tx-item">
                      <div className="tx-left">
                        <div className="tx-icon">{CATEGORY_ICONS[tx.category] || "💳"}</div>
                        <div>
                          <div className="tx-desc">{tx.desc}</div>
                          <div className="tx-meta">{tx.date} · {tx.category}</div>
                        </div>
                      </div>
                      <div className={`tx-amount ${tx.amount > 0 ? "credit" : "debit"}`}>
                        {tx.amount > 0 ? "+" : ""}${Math.abs(tx.amount).toFixed(2)}
                      </div>
                    </div>
                  ))}
                </div>
              </>
            )}

            {/* ACCOUNTS */}
            {activeTab === "accounts" && (
              <>
                <div className="cards-grid">
                  {MOCK_ACCOUNTS.map(acc => (
                    <div key={acc.id} className={`account-card ${acc.type}`}>
                      <div className="card-type">{acc.type}</div>
                      <div className="card-balance">${acc.balance.toLocaleString("en-US", { minimumFractionDigits: 2 })}</div>
                      <div className="card-name">{acc.name}</div>
                      <div className="card-id">{acc.id}</div>
                    </div>
                  ))}
                </div>
              </>
            )}

            {/* TRANSACTIONS */}
            {activeTab === "transactions" && (
              <>
                <div className="section-title">All Transactions</div>
                <div className="tx-list">
                  {MOCK_TRANSACTIONS.map(tx => (
                    <div key={tx.id} className="tx-item">
                      <div className="tx-left">
                        <div className="tx-icon">{CATEGORY_ICONS[tx.category] || "💳"}</div>
                        <div>
                          <div className="tx-desc">{tx.desc}</div>
                          <div className="tx-meta">{tx.date} · {tx.category}</div>
                        </div>
                      </div>
                      <div className={`tx-amount ${tx.amount > 0 ? "credit" : "debit"}`}>
                        {tx.amount > 0 ? "+" : ""}${Math.abs(tx.amount).toFixed(2)}
                      </div>
                    </div>
                  ))}
                </div>
              </>
            )}

            {/* TRANSFER */}
            {activeTab === "transfer" && (
              <div className="transfer-card">
                {transferDone ? (
                  <div className="transfer-success">
                    <div style={{ fontSize: 40, marginBottom: 12 }}>✓</div>
                    <div style={{ fontSize: 20, fontWeight: 700, marginBottom: 8 }}>Transfer Initiated</div>
                    <div style={{ color: "var(--muted)", fontFamily: "var(--mono)", fontSize: 13 }}>
                      ${transferAmt} → {transferTo}<br />
                      <span style={{ color: "var(--accent2)" }}>CORTEX cleared this transaction</span>
                    </div>
                    <button className="btn btn-ghost" style={{ marginTop: 20 }} onClick={() => { setTransferDone(false); setTransferAmt(""); setTransferTo(""); }}>
                      New Transfer
                    </button>
                  </div>
                ) : (
                  <>
                    <div className="section-title">Send Money</div>
                    <div className="field">
                      <label>From Account</label>
                      <select>
                        {MOCK_ACCOUNTS.map(a => <option key={a.id}>{a.name} — ${a.balance.toLocaleString()}</option>)}
                      </select>
                    </div>
                    <div className="field">
                      <label>Recipient</label>
                      <input value={transferTo} onChange={e => setTransferTo(e.target.value)} placeholder="Account number or username" />
                    </div>
                    <div className="field">
                      <label>Amount (USD)</label>
                      <input type="number" value={transferAmt} onChange={e => setTransferAmt(e.target.value)} placeholder="0.00" />
                    </div>
                    <button className="btn btn-primary" onClick={() => { if (transferAmt && transferTo) setTransferDone(true); }}>
                      Send Transfer
                    </button>
                    <div style={{ marginTop: 16, padding: 12, background: "rgba(0,212,255,0.05)", border: "1px solid rgba(0,212,255,0.1)", borderRadius: 8, fontSize: 12, fontFamily: "var(--mono)", color: "var(--muted)" }}>
                      ◈ CORTEX monitors all transactions for anomalous patterns in real-time.
                    </div>
                  </>
                )}
              </div>
            )}

            {/* ATTACK LAB */}
            {activeTab === "attacklab" && (
              <div className="attack-lab">
                <div className="attack-lab-title">⚡ CORTEX Attack Lab</div>
                <div className="attack-lab-sub">
                  Simulate real-world attacks against NexaBank and watch CORTEX respond in real-time.<br />
                  Make sure you are logged in with a valid username/password above.
                </div>

                <div style={{ marginBottom: 16, padding: "10px 14px", background: "rgba(0,212,255,0.05)", border: "1px solid rgba(0,212,255,0.1)", borderRadius: 8, fontFamily: "var(--mono)", fontSize: 12, color: "var(--muted)" }}>
                  Attacking as: <span style={{ color: "var(--accent)" }}>{currentUser?.username}</span> · Open <a href="http://127.0.0.1:5000/admin?token=cortex-admin-2025" target="_blank" rel="noreferrer" style={{ color: "var(--accent2)" }}>CORTEX Dashboard</a> side-by-side to watch live.
                </div>

                <div className="attack-grid">
                  {attacks.map(atk => (
                    <div key={atk.id} className={`attack-card ${activeAttack === atk.id ? "active" : ""}`} onClick={() => runAttack(atk)}
                      style={attackRunning && activeAttack !== atk.id ? { opacity: 0.4, pointerEvents: "none" } : {}}>
                      <div className="attack-card-icon">{atk.icon}</div>
                      <div className="attack-card-name">{atk.name}</div>
                      <div className="attack-card-desc">{atk.desc}</div>
                      <div className="attack-card-tag">{atk.tag}</div>
                    </div>
                  ))}
                </div>

                {(attackLogs.length > 0 || attackRunning) && (
                  <div className="attack-running">
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
                      <div style={{ fontSize: 12, fontFamily: "var(--mono)", color: "var(--muted)" }}>
                        {attackRunning ? "⚡ Attack in progress..." : "✓ Complete"}
                      </div>
                      <div style={{ fontSize: 12, fontFamily: "var(--mono)", color: "var(--accent)" }}>{attackProgress}%</div>
                    </div>
                    <div className="progress-wrap">
                      <div className="progress-bar" style={{ width: `${attackProgress}%` }} />
                    </div>
                    <div className="attack-log" ref={logRef}>
                      {attackLogs.map((l, i) => (
                        <div key={i} className={`log-line ${l.type}`}>{l.msg}</div>
                      ))}
                    </div>
                    <button className="btn btn-ghost" style={{ marginTop: 12 }} onClick={() => { setAttackLogs([]); setActiveAttack(null); setAttackProgress(0); }}>
                      Clear Log
                    </button>
                  </div>
                )}
              </div>
            )}

            {/* PROFILE */}
            {activeTab === "profile" && (
              <>
                <div style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 16, padding: 28, maxWidth: 520, marginBottom: 24 }}>
                  <div style={{ fontSize: 13, fontFamily: "var(--mono)", color: "var(--muted)", letterSpacing: 2, textTransform: "uppercase", marginBottom: 20 }}>Account Details</div>
                  <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 24 }}>
                    <div className="user-avatar" style={{ width: 52, height: 52, fontSize: 20, borderRadius: 12 }}>
                      {currentUser?.username?.[0]?.toUpperCase()}
                    </div>
                    <div>
                      <div style={{ fontSize: 20, fontWeight: 700 }}>{currentUser?.username}</div>
                      <div style={{ fontSize: 12, color: "var(--muted)", fontFamily: "var(--mono)" }}>User ID: #{currentUser?.userId}</div>
                    </div>
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
                    <div style={{ background: "var(--surface2)", padding: 16, borderRadius: 10, border: "1px solid var(--border)" }}>
                      <div style={{ fontSize: 10, color: "var(--muted)", fontFamily: "var(--mono)", letterSpacing: 1, marginBottom: 6 }}>RISK SCORE</div>
                      <div style={{ fontSize: 24, fontWeight: 800, color: sev === "high" ? "var(--danger)" : sev === "medium" ? "var(--warn)" : "var(--accent2)" }}>{currentUser?.riskScore ?? 0}</div>
                    </div>
                    <div style={{ background: "var(--surface2)", padding: 16, borderRadius: 10, border: "1px solid var(--border)" }}>
                      <div style={{ fontSize: 10, color: "var(--muted)", fontFamily: "var(--mono)", letterSpacing: 1, marginBottom: 6 }}>SEVERITY</div>
                      <div style={{ fontSize: 24, fontWeight: 800, color: sev === "high" ? "var(--danger)" : sev === "medium" ? "var(--warn)" : "var(--accent2)" }}>{(currentUser?.severity || "low").toUpperCase()}</div>
                    </div>
                  </div>
                  <div style={{ marginTop: 16, padding: 12, background: "rgba(0,212,255,0.05)", border: "1px solid rgba(0,212,255,0.1)", borderRadius: 8, fontSize: 12, fontFamily: "var(--mono)", color: "var(--muted)" }}>
                    ◈ Your session is actively monitored by CORTEX threat intelligence.
                  </div>
                </div>

                <div style={{ background: "var(--surface)", border: "1px solid rgba(255,59,92,0.2)", borderRadius: 16, padding: 28, maxWidth: 520 }}>
                  <div style={{ fontSize: 13, fontFamily: "var(--mono)", color: "var(--danger)", letterSpacing: 2, textTransform: "uppercase", marginBottom: 12 }}>Danger Zone</div>
                  <div style={{ fontSize: 13, color: "var(--muted)", marginBottom: 16, lineHeight: 1.6 }}>
                    Permanently delete your profile and all associated data including login history, risk scores, baselines, and enforcement logs. <strong style={{ color: "var(--danger)" }}>This action cannot be undone.</strong>
                  </div>
                  {deleteConfirm && (
                    <div style={{ padding: 12, background: "rgba(255,59,92,0.08)", border: "1px solid rgba(255,59,92,0.2)", borderRadius: 8, fontSize: 12, fontFamily: "var(--mono)", color: "var(--danger)", marginBottom: 12 }}>
                      ⚠ Are you sure? Click the button again to permanently delete your account.
                    </div>
                  )}
                  <button className="btn btn-danger" onClick={handleDeleteProfile} disabled={deleteLoading} style={{ maxWidth: 280 }}>
                    {deleteLoading ? <span className="spinner" /> : deleteConfirm ? "⚠ Confirm Permanent Deletion" : "Delete My Profile"}
                  </button>
                  {deleteConfirm && (
                    <button className="btn btn-ghost" style={{ maxWidth: 280, marginTop: 8 }} onClick={() => setDeleteConfirm(false)}>
                      Cancel
                    </button>
                  )}
                  {error && <div className="error-msg" style={{ textAlign: "left", marginTop: 12 }}>{error}</div>}
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="app">
      {page === "login" && renderLogin()}
      {page === "register" && renderRegister()}
      {page === "dashboard" && renderDashboard()}
    </div>
  );
}