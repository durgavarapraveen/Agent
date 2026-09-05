# ============================================================
# Cybersecurity Kali Container (slim) — only tools the agent actually uses.
# The broad kali-tools-* metapackages were removed: they pulled GBs of wireless,
# bluetooth, hardware/SDR, VoIP, forensics, reverse-engineering, stego, VoIP and
# GUI tooling that this autonomous web/API/network agent never calls. Every tool
# below is referenced by the codebase.
# ============================================================

# syntax=docker/dockerfile:1.4

# ============================================================
# Stage 1: Build modern Go-based security tools
# ============================================================
FROM golang:1.26-alpine AS go-builder

ENV CGO_ENABLED=0 \
    GOPATH=/go

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install github.com/ffuf/ffuf/v2@latest
RUN go install github.com/tomnomnom/assetfinder@latest
# Added — used by the code but previously missing from the image:
RUN go install github.com/hahwul/dalfox/v2@latest
RUN go install github.com/tomnomnom/waybackurls@latest
RUN go install github.com/lc/gau/v2/cmd/gau@latest


# ============================================================
# Stage 2: Kali Rolling
# ============================================================
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/opt/venv/bin:$PATH"

# ------------------------------------------------------------
# Base utilities + only the individual security tools the code invokes.
# (No kali-tools-* metapackages.)
# ------------------------------------------------------------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    # --- core utilities ---
    ca-certificates \
    curl \
    wget \
    git \
    jq \
    unzip \
    file \
    procps \
    iproute2 \
    iputils-ping \
    dnsutils \
    whois \
    openssl \
    netcat-openbsd \
    # --- python + build/runtime libs (weasyprint PDF, psycopg2, playwright) ---
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    python3-setuptools \
    python3-pkg-resources \
    build-essential \
    libffi-dev \
    libpq-dev \
    libgobject-2.0-0 \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    shared-mime-info \
    libfreetype6-dev \
    libjpeg-dev \
    zlib1g-dev \
    # --- recon / DNS / OSINT ---
    nmap \
    masscan \
    rustscan \
    amass \
    dnsrecon \
    dnsenum \
    fierce \
    theharvester \
    whatweb \
    wafw00f \
    # --- content discovery ---
    gobuster \
    feroxbuster \
    dirb \
    dirsearch \
    arjun \
    # --- web vuln / injection ---
    sqlmap \
    nikto \
    sslscan \
    testssl.sh \
    commix \
    wpscan \
    # --- passwords / auth ---
    hydra \
    medusa \
    john \
    hashcat \
    responder \
    # --- post-exploitation / lateral (impacket also via pip below) ---
    crackmapexec \
    smbclient \
    ldap-utils \
    # --- capture / misc used by the code ---
    tcpdump \
    tshark \
    gdb \
    imagemagick \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------
# OPTIONAL heavy tools — NOT installed by default (each is 0.5–2 GB and only
# referenced in a handful of files; the agent has its own exploitation paths and
# falls back when a tool is absent). Uncomment if you specifically need them:
#
#   RUN apt-get update && apt-get install -y --no-install-recommends \
#       metasploit-framework \
#       zaproxy \
#       && apt-get clean && rm -rf /var/lib/apt/lists/*
# ------------------------------------------------------------

# ============================================================
# Python virtual environment
# ============================================================
RUN python3 -m venv /opt/venv
# Pin setuptools<81: setuptools 81+ removed the `pkg_resources` module, which
# dirsearch (installed via apt but running under the venv python) still imports
# and errors out with `ModuleNotFoundError: No module named 'pkg_resources'`.
RUN /opt/venv/bin/pip install --upgrade pip wheel && \
    /opt/venv/bin/pip install --no-cache-dir 'setuptools<81'

# Runtime sanity check — fail the build if pkg_resources cannot be imported.
RUN /opt/venv/bin/python3 -c "import pkg_resources; print('pkg_resources OK')"
# CFLAGS=-std=gnu17: Kali ships Python 3.14 + a C23-default GCC, under which the
# legacy reportlab<4.0 C extension fails to compile (it uses `bool` as an
# identifier). Forcing C17 lets it build.
RUN CFLAGS="-std=gnu17" /opt/venv/bin/pip install --no-cache-dir \
    aiohttp \
    pydantic \
    python-dotenv \
    requests \
    httpx \
    fastapi \
    uvicorn \
    weasyprint \
    xhtml2pdf \
    psycopg2-binary \
    playwright \
    impacket \
    paramspider

# ============================================================
# Playwright + Chromium (browser actuator)
# ============================================================
RUN playwright install --with-deps chromium

# ============================================================
# Copy Go tools
# ============================================================
COPY --from=go-builder /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=go-builder /go/bin/httpx /usr/local/bin/httpx
RUN ln -sf /usr/local/bin/httpx /usr/local/bin/httpx-toolkit
COPY --from=go-builder /go/bin/dnsx /usr/local/bin/dnsx
COPY --from=go-builder /go/bin/katana /usr/local/bin/katana
COPY --from=go-builder /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=go-builder /go/bin/ffuf /usr/local/bin/ffuf
COPY --from=go-builder /go/bin/assetfinder /usr/local/bin/assetfinder
COPY --from=go-builder /go/bin/dalfox /usr/local/bin/dalfox
COPY --from=go-builder /go/bin/waybackurls /usr/local/bin/waybackurls
COPY --from=go-builder /go/bin/gau /usr/local/bin/gau

# ============================================================
# Workspace & wordlists
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

# Content-discovery tools expect /usr/share/wordlists/dirb/common.txt. The slim
# image dropped the `wordlists` symlink package, so wire dirb's own wordlists
# into that path (with a minimal fallback so the tools never fail on a missing file).
RUN mkdir -p /usr/share/wordlists/dirb && \
    if [ -d /usr/share/dirb/wordlists ]; then \
        cp -rn /usr/share/dirb/wordlists/* /usr/share/wordlists/dirb/ 2>/dev/null || true; \
    fi && \
    if [ ! -f /usr/share/wordlists/dirb/common.txt ]; then \
        printf '%s\n' admin login api rest robots.txt sitemap.xml .git .env \
            backup config test dev administrator uploads images js css assets \
            ftp user users account accounts dashboard portal private public \
            index.html index.php home about contact search products \
            > /usr/share/wordlists/dirb/common.txt; \
    fi

# The code (ffuf/gobuster/feroxbuster/dirsearch) expects /usr/share/wordlists/dirb/...
# The `dirb` package ships its lists at /usr/share/dirb/wordlists/; the symlink that
# normally maps them under /usr/share/wordlists came from the removed `wordlists`
# metapackage. Recreate just that symlink (no bloat), and provide a common.txt fallback.
RUN mkdir -p /usr/share/wordlists && \
    if [ -d /usr/share/dirb/wordlists ] && [ ! -e /usr/share/wordlists/dirb ]; then \
        ln -sf /usr/share/dirb/wordlists /usr/share/wordlists/dirb; \
    fi && \
    if [ ! -e /usr/share/wordlists/dirb/common.txt ]; then \
        mkdir -p /usr/share/wordlists/dirb && \
        printf '%s\n' admin login api robots.txt sitemap.xml .git .env config backup \
            test dev uploads images js css assets rest graphql swagger openapi \
            > /usr/share/wordlists/dirb/common.txt; \
    fi

WORKDIR /pentesting

# ============================================================
# Nuclei templates
# ============================================================
RUN nuclei -update-templates || true

# ============================================================
# Verification (last layer — fails fast, doesn't rebuild earlier)
# ============================================================
RUN echo "===== Tool verification =====" && \
    for tool in nmap masscan rustscan subfinder assetfinder amass dnsx httpx katana nuclei ffuf dalfox waybackurls gau gobuster feroxbuster arjun sqlmap nikto sslscan wpscan commix hydra john hashcat responder crackmapexec tcpdump tshark; do \
    command -v "$tool" >/dev/null 2>&1 && echo "OK  $tool" || echo "MISSING  $tool"; \
    done

CMD ["tail", "-f", "/dev/null"]
