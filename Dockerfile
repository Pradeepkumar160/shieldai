FROM python:3.11-slim

WORKDIR /app

COPY shieldai.py .

RUN pip install --no-cache-dir fastapi uvicorn pydantic-settings python-dotenv httpx

EXPOSE 8000

CMD ["python", "shieldai.py"]
