"""Generate deployment topology; no runtime secrets enter the image."""
from pathlib import Path

base=Path(__file__).resolve().parents[1]
services=["name: witness-quorum", "services:"]
for i in range(1,8):
    services.extend(f"""  witness-{i}:
    build: .
    image: witness-quorum:research
    command: ["--root", "/runtime", "--id", "{i}", "--engine", "/app/bin/witness-engine"]
    restart: unless-stopped
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    pids_limit: 128
    mem_limit: 512m
    cpus: 1.0
    tmpfs: [/tmp:size=32m]
    volumes:
      - ./runtime/docker/genesis.json:/runtime/genesis.json:ro
      - ./runtime/docker/admin.pub:/runtime/admin.pub:ro
      - ./runtime/docker/secrets/node-{i}.json:/runtime/secrets/node-{i}.json:ro
      - ./runtime/docker/data/node-{i}:/runtime/data/node-{i}
    networks: [witness]
    healthcheck:
      test: ["CMD", "python", "-c", "import socket; socket.create_connection(('127.0.0.1',{10100+i}),2).close()"]
      interval: 10s
      timeout: 3s
      retries: 6
""".splitlines())
services.extend("""  client:
    image: witness-quorum:research
    profiles: [tools]
    entrypoint: [python, -m, witness.client]
    command: [status, --root, /runtime]
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    volumes:
      - ./runtime/docker/genesis.json:/runtime/genesis.json:ro
      - ./runtime/docker/admin.pub:/runtime/admin.pub:ro
      - ./runtime/docker/secrets/client.json:/runtime/secrets/client.json:ro
      - ./runtime/docker/client-events:/runtime/client-events
    networks: [witness]
networks:
  witness:
    internal: true
""".splitlines())
(base/"compose.yaml").write_text("\n".join(services)+"\n")
