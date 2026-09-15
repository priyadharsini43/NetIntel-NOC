# ============================================================
# Stage 1: Build React Frontend
# ============================================================

FROM node:20-alpine AS frontend-build

WORKDIR /frontend

# Copy frontend package files first
# This allows Docker to cache npm dependencies
COPY frontend/package*.json ./

# Install frontend dependencies
RUN npm ci

# Copy frontend source code
COPY frontend/ .

# Build React application
RUN npm run build


# ============================================================
# Stage 2: Flask Backend
# ============================================================

FROM python:3.11-slim

WORKDIR /app

# ------------------------------------------------------------
# Install system dependencies required by Scapy
# ------------------------------------------------------------

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpcap-dev \
    tcpdump \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*


# ------------------------------------------------------------
# Install Python dependencies
# ------------------------------------------------------------

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt


# ------------------------------------------------------------
# Copy complete project
# ------------------------------------------------------------

COPY . .


# ------------------------------------------------------------
# Copy React production build from Stage 1
# ------------------------------------------------------------

COPY --from=frontend-build /frontend/dist ./frontend/dist


# ------------------------------------------------------------
# Flask / Render configuration
# ------------------------------------------------------------

EXPOSE 5000

ENV FLASK_ENV=production
ENV PORT=5000


# ------------------------------------------------------------
# Start Flask using Gunicorn
# ------------------------------------------------------------

CMD ["gunicorn", "--worker-class", "gthread", "--workers", "2", "--threads", "4", "--bind", "0.0.0.0:5000", "app:app"]