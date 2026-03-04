FROM python:3.13-slim

# Apply security patches
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

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
COPY loads_db.py .

EXPOSE ${PORT:-5000}

CMD ["gunicorn", "railway:app", "--bind", "0.0.0.0:5000", "--workers", "1", "--timeout", "120"]

