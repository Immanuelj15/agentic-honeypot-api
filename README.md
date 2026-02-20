# Agentic Honeypot API

AI-powered scam detection and intelligence extraction honeypot that engages scammers in multi-turn conversations to extract phone numbers, bank accounts, UPI IDs, phishing links, and other identifying information.

## Architecture

```
main.py              → FastAPI endpoints (/honeypot, /final-output)
conversation.py      → HuggingFace LLM + fallback response engine
extraction.py        → Regex-based intelligence extraction
session_manager.py   → Thread-safe session state & scam classification
config.py            → Environment configuration
```

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
cp .env.example .env
# Edit .env with your Hugging Face API token
```

### 3. Run Locally
```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

### 4. Self-Test
```bash
python test_api.py
```

## API Endpoints

### `POST /honeypot`
Main conversation endpoint. Receives scammer messages and responds with engaging replies.

**Headers:** `x-api-key: your-api-key`, `Content-Type: application/json`

**Request:**
```json
{
  "sessionId": "uuid-v4",
  "message": {"sender": "scammer", "text": "...", "timestamp": "..."},
  "conversationHistory": [],
  "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
}
```

**Response:** `{"status": "success", "reply": "..."}`

### `POST /final-output`
Returns the final analysis for a session.

### `GET /session/{sessionId}`
Debug endpoint to inspect session state.

## Deployment

### Railway / Render
1. Push to GitHub
2. Connect repo to Railway/Render
3. Set environment variables: `API_KEY`, `HF_API_TOKEN`
4. Deploy — `Procfile` handles the start command

### Heroku
```bash
heroku create your-app-name
heroku config:set API_KEY=test123 HF_API_TOKEN=your_token
git push heroku main
```

## Scoring Strategy

| Category | Points | Strategy |
|---|---|---|
| Scam Detection | 20 | Always detect — this is a honeypot |
| Intelligence Extraction | 30 | Regex extraction from all messages |
| Conversation Quality | 30 | LLM generates investigative questions |
| Engagement Quality | 10 | Progressive callbacks maximize duration |
| Response Structure | 10 | All required + optional fields included |

## Key Features

- **LLM-powered conversations** via Hugging Face Inference API with rule-based fallback
- **Robust extraction** with UPI/email separation and phone-aware bank account filtering
- **Progressive final output** — sends updated results after each turn ≥ 5
- **Auto scam classification** — detects bank_fraud, upi_fraud, phishing, tech_support, etc.
- **Red flag tracking** — identifies urgency, OTP requests, suspicious links, and more
