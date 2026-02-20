"""
Configuration for the Honeypot API.
"""

import os

API_KEY = os.getenv("API_KEY", "test123")
GUVI_CALLBACK_URL = os.getenv(
    "GUVI_CALLBACK_URL",
    "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
)
HF_API_TOKEN = os.getenv("HF_API_TOKEN", "")
HF_MODEL = os.getenv("HF_MODEL", "mistralai/Mistral-7B-Instruct-v0.3")
FINAL_OUTPUT_MIN_TURN = 5
MAX_TURNS = 10
