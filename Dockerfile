FROM python:3.11-slim

RUN apt-get update && apt-get install -y curl procps zstd && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://ollama.com/install.sh | sh

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY index_railway.py .

RUN ollama serve & sleep 5 && ollama pull llama3.2:3b && pkill ollama

COPY start.sh .
RUN sed -i 's/\r$//' start.sh && chmod +x start.sh

EXPOSE ${PORT:-5000}

CMD ["./start.sh"]
