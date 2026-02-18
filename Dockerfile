FROM python:3.11-slim

# Install dependencies
RUN apt-get update && apt-get install -y curl procps && rm -rf /var/lib/apt/lists/*

# Install Ollama
RUN curl -fsSL https://ollama.com/install.sh | sh

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY index_railway.py .

# Pull model at build time (baked into the image — no download at runtime)
# Using llama3.2:1b (1.3GB) — smallest model that handles route logic well
RUN ollama serve & sleep 5 && ollama pull llama3.2:1b && pkill ollama

# Start script: launch Ollama in background, then Flask
COPY start.sh .
RUN chmod +x start.sh

EXPOSE ${PORT:-5000}

CMD ["./start.sh"]
