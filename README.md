# ShieldAI — LLM Security Gateway

A production-ready prompt injection and jailbreak detector.

## Run locally
pip install fastapi uvicorn pydantic-settings python-dotenv httpx
python shieldai.py

## Run with Docker
docker build -t shieldai .
docker run -p 8000:8000 shieldai

## Open
http://localhost:8000
