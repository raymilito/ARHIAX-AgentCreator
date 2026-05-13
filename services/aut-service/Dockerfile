FROM python:3.12-slim
WORKDIR /app

RUN apt-get update     && apt-get install -y --no-install-recommends curl     && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
RUN mkdir -p /data /certs

EXPOSE 8201

# TLS: uvicorn usa el certificado montado en /certs/<svc-name>.{crt,key}
# Si los certificados no existen (dev local), arranca sin TLS como fallback.
CMD ["sh", "-c", "if [ -f /certs/aut-service.crt ] && [ -f /certs/aut-service.key ]; then   TLS_ARGS=\"--ssl-certfile /certs/aut-service.crt --ssl-keyfile /certs/aut-service.key\";   if [ -f /certs/ca.crt ] && [ \"${ARHIAX_REQUIRE_MTLS:-true}\" = \"true\" ]; then     TLS_ARGS=\"$TLS_ARGS --ssl-ca-certs /certs/ca.crt --ssl-cert-reqs 2\";   fi;   echo \"INFO: starting with TLS args: $TLS_ARGS\";   exec uvicorn main:app --host 0.0.0.0 --port 8201 $TLS_ARGS; else   echo \"WARN: TLS certs not found, starting without TLS (dev mode)\";   exec uvicorn main:app --host 0.0.0.0 --port 8201; fi"]
