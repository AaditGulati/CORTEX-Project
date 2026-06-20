# CORTEX — Context-Aware Authentication Threat Intelligence System

A rule-based behavioural authentication engine that dynamically 
evaluates login risk using a 13-module pipeline integrating 
behavioural baseline profiling, impossible travel detection, 
session fingerprinting, threat intelligence feed matching, and 
cumulative risk memory with time-bounded decay.

## The Problem
Traditional systems check the password and move on.
No memory. No context. No intelligence.
Modern attackers exploit exactly that.


## What CORTEX Does
- Runs a **13-module deterministic pipeline** on every login
- Assigns a **cumulative risk score** across sessions
- Enforces **4 levels of response** — from a delay to a full IP block
- Generates a **fully explainable rationale** for every decision
- Detects brute force, impossible travel, SQL injection, 
  credential stuffing, Tor exit nodes, and velocity attacks


## Tech Stack
- Backend: Python, Flask
- Database: SQLite
- Frontend: React + Vite (NexaBank simulation)
- Password Hashing: PBKDF2-SHA256

## Setup
```bash
pip install -r requirements.txt
python app.py
```

## Project Structure
- `app.py` — Application entry point
- `engine/` — 13-module security pipeline
- `auth/` — Authentication handlers
- `explainability/` — Decision rationale engine
- `nexabank/` — Simulated banking frontend
- `utils/` — Utilities