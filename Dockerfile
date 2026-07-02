FROM kalilinux/kali-rolling:latest

LABEL maintainer="ORACLE Project" \
      description="ORACLE v3.2 — Autonomous AI Red Team Intelligence System" \
      version="3.2.0"

# ── System tools ──────────────────────────────────────────────────────────────
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        nmap curl gobuster ffuf \
        wordlists \
        && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ───────────────────────────────────────────────────────
WORKDIR /oracle
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# ── Copy project ──────────────────────────────────────────────────────────────
COPY . .
RUN pip3 install --no-cache-dir -e .

# ── Runtime config ────────────────────────────────────────────────────────────
ENV ORACLE_API_KEY=""
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

# ── Entrypoint ────────────────────────────────────────────────────────────────
ENTRYPOINT ["python3", "-m", "oracle"]
CMD ["--demo"]
