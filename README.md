Threat Normalizer AI — Unified Log Normalization & Severity Engine

Threat Normalizer AI is a lightweight, fast, and ML-assisted log normalizer built to convert raw, unstructured security logs into standardized JSON events with severity scoring, correlation tags, and real-time streaming UI.

Designed for SOC teams, DFIR analysts, and automated pipelines.
🚀 Features
✔ AI-Powered Normalization

Automatically detects log type:
Firewall
IDS/IPS
Sysmon
Authentication logs
Web server logs
Linux audit logs

Maps it to:
timestamp
src_ip, dst_ip
action
severity
message

✔ Real-Time Log Stream Dashboard
Live UI built using Flask + SSE
Auto-updating table
Color-coded severity (green → yellow → red)
Live parsed and normalized fields
Fast response under 20ms

✔ Upload Raw Logs
Upload a .txt file → instantly normalized → exported as JSON.

✔ Cloud Ready
Drop-in containerization using run.sh and lightweight Python dependencies.

🧠 Architecture
raw logs  →  parser engine  →  normalizer  →  severity engine  →  UI stream

Modules
parser.py — detects log family
normalize.py — extracts structured fields
severity.py — assigns BaseScore (0–100)
app.py — live dashboard
templates/index.html — real-time UI

📦 Installation
git clone https://github.com/blacklatch-cybersecurity/threat-normalizer-ai.git
cd threat-normalizer-ai
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py


Dashboard opens at:
http://127.0.0.1:9100

🔥 API Usage
Normalize a single log
curl -X POST http://127.0.0.1:9100/api/normalize \
-H "Content-Type: application/json" \
-d '{"log": "Failed password for root from 192.168.1.10 port 54321"}'

Upload raw log file
POST /api/upload


Response: JSON array of normalized logs.

🌈 Severity Colors
Severity	Score	Color
Low	0–30	Green
Medium	31–70	Yellow
High	71–100	Red

🛡 Future Add-Ons
MITRE ATT&CK mapping
Elastic/Splunk connector
Threat enrichment (VirusTotal / AbuseIPDB)
Log correlation with Project 9

👤 Author
Blacklatch Cybersecurity Defense
Cybersecurity CEO · SOC Architect · Threat Intelligence Engineer
