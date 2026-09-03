# ============================================================
# Comprehensive Cybersecurity Kali Container
# ============================================================

# Syntax hint for BuildKit (enables better caching)
# syntax=docker/dockerfile:1.4

# ============================================================
# Stage 1: Build modern Go-based security tools
# ============================================================

FROM golang:1.26-alpine AS go-builder

ENV CGO_ENABLED=0 \
    GOPATH=/go

# Separate installs = separate cache layers (fail faster on individual tool issues)
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install github.com/ffuf/ffuf/v2@latest
RUN go install github.com/tomnomnom/assetfinder@latest


# ============================================================
# Stage 2: Kali Rolling
# ============================================================

FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/opt/venv/bin:$PATH"

# ============================================================
# All packages in one layer (fastest, no layer overhead)
# ============================================================

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    apt-transport-https \
    curl \
    wget \
    git \
    vim \
    nano \
    tmux \
    screen \
    jq \
    unzip \
    zip \
    file \
    tree \
    rsync \
    procps \
    lsof \
    net-tools \
    iproute2 \
    iputils-ping \
    traceroute \
    dnsutils \
    whois \
    socat \
    netcat-openbsd \
    openssh-client \
    openssl \
    gnupg \
    less \
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    build-essential \
    libpq-dev \
    libgobject-2.0-0 \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
    libfreetype6-dev \
    libjpeg-dev \
    zlib1g-dev \
    kali-tools-top10 \
    kali-tools-information-gathering \
    kali-tools-vulnerability \
    kali-tools-web \
    kali-tools-passwords \
    kali-tools-wireless \
    kali-tools-exploitation \
    kali-tools-social-engineering \
    kali-tools-sniffing-spoofing \
    kali-tools-post-exploitation \
    kali-tools-forensics \
    kali-tools-reverse-engineering \
    kali-tools-crypto-stego \
    kali-tools-reporting \
    kali-tools-identify \
    kali-tools-database \
    kali-tools-voip \
    kali-tools-hardware \
    kali-tools-bluetooth \
    nmap \
    masscan \
    rustscan \
    amass \
    dnsrecon \
    dnsenum \
    fierce \
    theharvester \
    recon-ng \
    spiderfoot \
    whatweb \
    wafw00f \
    gobuster \
    feroxbuster \
    dirb \
    dirsearch \
    sqlmap \
    nikto \
    sslscan \
    testssl.sh \
    commix \
    hydra \
    medusa \
    john \
    hashcat \
    hashcat-utils \
    crunch \
    responder \
    mitmproxy \
    tcpdump \
    tshark \
    wireshark-common \
    yara \
    binwalk \
    exiftool \
    foremost \
    steghide \
    radare2 \
    gdb \
    strace \
    ltrace \
    smbclient \
    ldap-utils \
    docker.io \
    imagemagick \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ============================================================
# Layer 5: Python virtual environment (separate layer)
# ============================================================

RUN python3.11 -m venv /opt/venv

RUN /opt/venv/bin/pip install --upgrade pip setuptools wheel

RUN /opt/venv/bin/pip install --no-cache-dir \
    aiohttp \
    pydantic \
    python-dotenv \
    requests \
    httpx \
    fastapi \
    uvicorn \
    weasyprint \
    "reportlab<4.0" \
    xhtml2pdf \
    psycopg2-binary \
    playwright

# ============================================================
# Layer 6: Playwright + Chromium (can be slow/fail independently)
# ============================================================

RUN playwright install --with-deps chromium

# ============================================================
# Layer 7: Copy Go tools
# ============================================================

COPY --from=go-builder /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=go-builder /go/bin/httpx /usr/local/bin/httpx
RUN ln -sf /usr/local/bin/httpx /usr/local/bin/httpx-toolkit
COPY --from=go-builder /go/bin/dnsx /usr/local/bin/dnsx
COPY --from=go-builder /go/bin/katana /usr/local/bin/katana
COPY --from=go-builder /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=go-builder /go/bin/ffuf /usr/local/bin/ffuf
COPY --from=go-builder /go/bin/assetfinder /usr/local/bin/assetfinder

# ============================================================
# Layer 8: Workspace & wordlists
# ============================================================

RUN mkdir -p \
    /pentesting/reports \
    /pentesting/payloads \
    /pentesting/loot \
    /pentesting/logs \
    /pentesting/data \
    /pentesting/wordlists \
    /pentesting/tools \
    /usr/share/wordlists

RUN if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then \
    gunzip -f /usr/share/wordlists/rockyou.txt.gz; \
    fi

WORKDIR /pentesting

# ============================================================
# Layer 9: Nuclei templates (can fail, needs its own layer)
# ============================================================

RUN nuclei -update-templates || true

# ============================================================
# Layer 10: Verification (last layer—fails fast here, doesn't rebuild earlier)
# ============================================================

RUN echo "===== Tool verification =====" && \
    for tool in nmap masscan rustscan subfinder assetfinder amass dnsx httpx katana nuclei ffuf gobuster feroxbuster sqlmap nikto hydra john hashcat tcpdump tshark yara binwalk exiftool radare2 gdb; do \
    command -v "$tool" && echo "✓ $tool" || echo "✗ $tool"; \
    done

# ============================================================
# Container
# ============================================================

CMD ["tail", "-f", "/dev/null"]