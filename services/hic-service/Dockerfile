FROM python:3.12-slim
WORKDIR /app

RUN apt-get update     && apt-get install -y --no-install-recommends curl     && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
RUN mkdir -p /data /certs

EXPOSE 8203

# TLS: uvicorn usa el certificado montado en /certs/<svc-name>.{crt,key}
# Si los certificados no existen (dev local), arranca sin TLS como fallback.
CMD ["sh", "-c",   "if [ -f /certs/hic-service.crt ] && [ -f /certs/hic-service.key ]; then      exec uvicorn main:app --host 0.0.0.0 --port 8203        --ssl-certfile /certs/hic-service.crt        --ssl-keyfile  /certs/hic-service.key;    else      echo 'WARN: TLS certs not found, starting without TLS (dev mode)' &&      exec uvicorn main:app --host 0.0.0.0 --port 8203;    fi"]
