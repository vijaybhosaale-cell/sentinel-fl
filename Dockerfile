FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PYTHONUNBUFFERED=1 ARIA_USE_LLM=1 OLLAMA_URL=http://ollama:11434
EXPOSE 8000 8101
CMD ["python", "-m", "sentinel", "aggregator", "--host", "0.0.0.0", "--port", "8000"]
