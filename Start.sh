#!/bin/bash

# Start Ollama in background
echo "Starting Ollama..."
ollama serve &
OLLAMA_PID=$!

# Wait for Ollama to be ready
for i in {1..30}; do
    if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        echo "Ollama ready"
        break
    fi
    sleep 1
done

# Start gunicorn
echo "Starting gunicorn on port ${PORT:-5000}..."
exec gunicorn railway:app --bind 0.0.0.0:${PORT:-5000} --workers 2 --timeout 120
