import os
from dotenv import load_dotenv

load_dotenv()

# API Authentication
API_KEY = os.getenv("API_KEY", "test123")

# Hugging Face Inference API
HF_API_TOKEN = os.getenv("HF_API_TOKEN", "")
HF_MODEL = os.getenv("HF_MODEL", "mistralai/Mistral-7B-Instruct-v0.3")
HF_API_URL = f"https://api-inference.huggingface.co/models/{HF_MODEL}"

# Callback
GUVI_CALLBACK_URL = os.getenv(
    "GUVI_CALLBACK_URL",
    "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
)

# Conversation
MAX_TURNS = 10
FINAL_OUTPUT_MIN_TURN = 5  # Start sending progressive final outputs after this turn
