#!/bin/bash

echo "Starting Ollama..."
ollama serve &

for i in $(seq 1 30); do
    if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        echo "Ollama ready"
        break
    fi
    sleep 1
done

echo "Starting Flask on port ${PORT:-5000}..."
exec python index_railway.py
