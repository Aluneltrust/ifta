FROM python:3.13-slim

# Install dependencies and apply security patches
RUN apt-get update && apt-get upgrade -y && apt-get install -y curl procps zstd && rm -rf /var/lib/apt/lists/*

# Install Ollama
RUN curl -fsSL https://ollama.com/install.sh | sh

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all app files
COPY railway.py .
COPY config.py .
COPY auth.py .
COPY database.py .
COPY email_service.py .
COPY sms.py .
COPY route_optimizer.py .

# Pull model at build time (baked into the image — no download at runtime)
# Using llama3.2:1b (1.3GB) — smallest model that handles route logic well
RUN ollama serve & sleep 5 && ollama pull llama3.2:1b && pkill ollama

# Start script: launch Ollama in background, then Flask
COPY Start.sh .
RUN chmod +x Start.sh

EXPOSE ${PORT:-5000}

CMD ["./Start.sh"]
