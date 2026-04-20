FROM python:3.12-slim
WORKDIR /app

RUN apt-get update     && apt-get install -y --no-install-recommends curl     && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
RUN mkdir -p /data /certs

EXPOSE 8300

# TLS: uvicorn usa el certificado montado en /certs/<svc-name>.{crt,key}
# Si los certificados no existen (dev local), arranca sin TLS como fallback.
CMD ["sh", "-c",   "if [ -f /certs/creator-api.crt ] && [ -f /certs/creator-api.key ]; then      exec uvicorn main:app --host 0.0.0.0 --port 8300        --ssl-certfile /certs/creator-api.crt        --ssl-keyfile  /certs/creator-api.key;    else      echo 'WARN: TLS certs not found, starting without TLS (dev mode)' &&      exec uvicorn main:app --host 0.0.0.0 --port 8300;    fi"]
