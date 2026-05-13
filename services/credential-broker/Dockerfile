FROM python:3.12-slim
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
RUN mkdir -p /certs

EXPOSE 8204

CMD ["sh", "-c", "if [ -f /certs/credential-broker.crt ] && [ -f /certs/credential-broker.key ]; then   TLS_ARGS=\"--ssl-certfile /certs/credential-broker.crt --ssl-keyfile /certs/credential-broker.key\";   if [ -f /certs/ca.crt ] && [ \"${ARHIAX_REQUIRE_MTLS:-true}\" = \"true\" ]; then     TLS_ARGS=\"$TLS_ARGS --ssl-ca-certs /certs/ca.crt --ssl-cert-reqs 2\";   fi;   echo \"INFO: starting with TLS args: $TLS_ARGS\";   exec uvicorn main:app --host 0.0.0.0 --port 8204 $TLS_ARGS; else   echo \"WARN: TLS certs not found, starting without TLS (dev mode)\";   exec uvicorn main:app --host 0.0.0.0 --port 8204; fi"]
