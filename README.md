# Agentic Honeypot API

This is a basic FastAPI honeypot endpoint created for validation testing.

## Endpoint
POST /honeypot

## Authentication
Header:
x-api-key: test123

## Run locally
uvicorn main:app --reload --port 3000
