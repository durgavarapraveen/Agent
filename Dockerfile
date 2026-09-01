# ============================================================
# Comprehensive Cybersecurity Kali Container
# ============================================================

# ------------------------------------------------------------
# Stage 1: Build modern Go-based security tools
# ------------------------------------------------------------

FROM golang:1.26-alpine AS go-builder

ENV CGO_ENABLED=0 \
    GOPATH=/go

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/tomnomnom/assetfinder@latest


# ============================================================
# Stage 2: Kali Rolling
# ============================================================

FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/opt/venv/bin:$PATH"


# ============================================================
# Base system
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
    \
    # Python
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    build-essential \
    \
    # Database connectivity
    libpq-dev \
    \
    # Reporting / PDF
    libgobject-2.0-0 \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
    \
    # Kali cybersecurity categories
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
    \
    # Useful additional categories
    kali-tools-identify \
    kali-tools-database \
    kali-tools-voip \
    kali-tools-hardware \
    kali-tools-bluetooth \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


# ============================================================
# Additional commonly used tools
# ============================================================

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    nmap \
    masscan \
    rustscan \
    \
    amass \
    dnsrecon \
    dnsenum \
    fierce \
    theharvester \
    recon-ng \
    spiderfoot \
    \
    whatweb \
    wafw00f \
    \
    gobuster \
    feroxbuster \
    dirb \
    dirsearch \
    \
    sqlmap \
    nikto \
    sslscan \
    testssl.sh \
    commix \
    \
    hydra \
    medusa \
    john \
    hashcat \
    hashcat-utils \
    crunch \
    \
    responder \
    mitmproxy \
    \
    tcpdump \
    tshark \
    wireshark-common \
    \
    yara \
    binwalk \
    exiftool \
    foremost \
    steghide \
    \
    radare2 \
    gdb \
    strace \
    ltrace \
    \
    smbclient \
    ldap-utils \
    \
    docker.io \
    \
    imagemagick \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


# ============================================================
# Python virtual environment
# ============================================================

RUN python3 -m venv /opt/venv

RUN pip install --upgrade pip setuptools wheel && \
    pip install --no-cache-dir \
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

# Install the Chromium browser Playwright drives (with its OS dependencies) so the
# in-container request-capture crawler works instead of falling back to the host.
RUN playwright install --with-deps chromium


# ============================================================
# Copy Go-based tools
# ============================================================

COPY --from=go-builder /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=go-builder /go/bin/httpx /usr/local/bin/httpx
# The tool router invokes the ProjectDiscovery binary as `httpx-toolkit` (Kali's name
# for it, to avoid clashing with the python3-httpx library). Provide that alias.
RUN ln -sf /usr/local/bin/httpx /usr/local/bin/httpx-toolkit
COPY --from=go-builder /go/bin/dnsx /usr/local/bin/dnsx
COPY --from=go-builder /go/bin/katana /usr/local/bin/katana
COPY --from=go-builder /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=go-builder /go/bin/ffuf /usr/local/bin/ffuf
COPY --from=go-builder /go/bin/assetfinder /usr/local/bin/assetfinder


# ============================================================
# Workspace
# ============================================================

WORKDIR /pentesting

RUN mkdir -p \
    /pentesting/reports \
    /pentesting/payloads \
    /pentesting/loot \
    /pentesting/logs \
    /pentesting/data \
    /pentesting/wordlists \
    /pentesting/tools


# ============================================================
# Wordlists
# ============================================================

RUN mkdir -p /usr/share/wordlists && \
    if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then \
    gunzip -f /usr/share/wordlists/rockyou.txt.gz; \
    fi


# ============================================================
# Nuclei templates
# ============================================================

RUN nuclei -update-templates || true


# ============================================================
# Tool verification
# ============================================================

RUN echo "===== Cybersecurity tool verification =====" && \
    command -v nmap || true && \
    command -v masscan || true && \
    command -v rustscan || true && \
    command -v subfinder || true && \
    command -v assetfinder || true && \
    command -v amass || true && \
    command -v dnsx || true && \
    command -v httpx || true && \
    command -v katana || true && \
    command -v nuclei || true && \
    command -v ffuf || true && \
    command -v gobuster || true && \
    command -v feroxbuster || true && \
    command -v sqlmap || true && \
    command -v nikto || true && \
    command -v hydra || true && \
    command -v john || true && \
    command -v hashcat || true && \
    command -v tcpdump || true && \
    command -v tshark || true && \
    command -v yara || true && \
    command -v binwalk || true && \
    command -v exiftool || true && \
    command -v radare2 || true && \
    command -v gdb || true


# ============================================================
# Container
# ============================================================

CMD ["tail", "-f", "/dev/null"]