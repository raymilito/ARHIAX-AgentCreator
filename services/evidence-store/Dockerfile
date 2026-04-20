FROM python:3.12-slim
WORKDIR /app

RUN apt-get update     && apt-get install -y --no-install-recommends curl     && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
RUN mkdir -p /data /certs

EXPOSE 8090

# TLS: uvicorn usa el certificado montado en /certs/<svc-name>.{crt,key}
# Si los certificados no existen (dev local), arranca sin TLS como fallback.
CMD ["sh", "-c",   "if [ -f /certs/evidence-store.crt ] && [ -f /certs/evidence-store.key ]; then      exec uvicorn main:app --host 0.0.0.0 --port 8090        --ssl-certfile /certs/evidence-store.crt        --ssl-keyfile  /certs/evidence-store.key;    else      echo 'WARN: TLS certs not found, starting without TLS (dev mode)' &&      exec uvicorn main:app --host 0.0.0.0 --port 8090;    fi"]
