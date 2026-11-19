FROM golang:1.27.3-bookworm AS engine
WORKDIR /src
COPY vendor-source/SmartBFT /src/vendor-source/SmartBFT
COPY engine /src/engine
WORKDIR /src/engine
RUN CGO_ENABLED=0 go build -trimpath -o /witness-engine .

FROM python:3.12-slim-bookworm
RUN useradd --uid 10001 --create-home witness
WORKDIR /app
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock
COPY witness ./witness
COPY --from=engine /witness-engine /app/bin/witness-engine
USER 10001:10001
ENV PYTHONUNBUFFERED=1 WITNESS_BIND=0.0.0.0
ENTRYPOINT ["python", "-m", "witness.node"]
