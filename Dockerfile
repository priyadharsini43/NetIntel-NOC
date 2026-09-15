FROM python:3.11-slim

WORKDIR /app

# Install system network tools and libpcap for Scapy
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpcap-dev \
    tcpdump \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

ENV FLASK_ENV=production
ENV PORT=5000

CMD ["gunicorn", "--worker-class", "gthread", "--workers", "2", "--threads", "4", "--bind", "0.0.0.0:5000", "app:app"]
