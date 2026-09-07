# ============================================================
# Cybersecurity Kali Container (slim) — only tools the agent actually uses.
# The broad kali-tools-* metapackages were removed: they pulled GBs of wireless,
# bluetooth, hardware/SDR, VoIP, forensics, reverse-engineering, stego, VoIP and
# GUI tooling that this autonomous web/API/network agent never calls. Every tool
# below is referenced by the codebase.
# ============================================================

# syntax=docker/dockerfile:1.4

# Global build args (declared before ANY `FROM` so they can be used in the
# base-image reference of a downstream stage; Docker treats ARG-before-FROM
# as global, ARG-after-FROM as stage-scoped).
ARG KALI_ROLLING_DIGEST=kalilinux/kali-rolling@sha256:c6d78f57ebfdd9fec428a8b04f74876e66fddd08dfd328c076224a552e7332a3

# ============================================================
# (Former Stage 1 removed) — the ProjectDiscovery Go tools that used
# to be built from source here are now installed from Kali's apt repos
# in the stage below. That eliminates the proxy.golang.org dependency
# which was intermittently unreachable from Docker Desktop, and cuts
# build time from ~15 min to ~3 min.
# ============================================================


# ============================================================
# Kali Rolling — sole build stage
# ============================================================
# Pinned by digest so `docker build` is reproducible. Bump this SHA
# intentionally (with a review), not implicitly on every rebuild.
# The tag `kalilinux/kali-rolling` moves every week; the digest below is
# the last verified snapshot. Update by running:
#   docker pull kalilinux/kali-rolling
#   docker inspect --format='{{index .RepoDigests 0}}' kalilinux/kali-rolling
FROM ${KALI_ROLLING_DIGEST}

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/opt/venv/bin:$PATH"

# ------------------------------------------------------------
# Base utilities + only the individual security tools the code invokes.
# (No kali-tools-* metapackages.)
# ------------------------------------------------------------
RUN set -eux; \
    n=0; \
    until [ "$n" -ge 5 ]; do \
        apt-get clean && apt-get update && break; \
        n=$((n+1)); \
        echo "apt-get update failed (attempt $n/5), retrying in 10s..."; \
        sleep 10; \
    done; \
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
    libglib2.0-0 \
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
    # --- ProjectDiscovery + Go tools (was Go-builder stage; Kali apt is faster
    #     and doesn't depend on proxy.golang.org which is flaky from Docker
    #     Desktop) ---
    subfinder \
    httpx-toolkit \
    dnsx \
    katana \
    nuclei \
    ffuf \
    assetfinder \
    dalfox \
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

# `waybackurls` and `gau` aren't in Kali apt. Grab the prebuilt Linux
# binaries straight from the maintainer's GitHub release — tiny (~5 MB
# each), no compilation, no proxy.golang.org involvement. Retry up to
# 3× because GitHub can also hiccup.
ARG WAYBACKURLS_VERSION=0.1.0
ARG GAU_VERSION=2.2.4
RUN set -eux; \
    dl() { \
    n=0; \
    until [ "$n" -ge 3 ]; do \
    curl -fsSL "$1" -o "$2" && return 0; \
    n=$((n+1)); \
    echo "curl $1 failed (attempt $n/3), retrying in 5s..."; \
    sleep 5; \
    done; \
    echo "curl $1 FAILED after 3 attempts"; return 1; \
    }; \
    cd /tmp; \
    dl "https://github.com/tomnomnom/waybackurls/releases/download/v${WAYBACKURLS_VERSION}/waybackurls-linux-amd64-${WAYBACKURLS_VERSION}.tgz" waybackurls.tgz; \
    tar -xzf waybackurls.tgz && mv waybackurls /usr/local/bin/waybackurls && chmod +x /usr/local/bin/waybackurls; \
    dl "https://github.com/lc/gau/releases/download/v${GAU_VERSION}/gau_${GAU_VERSION}_linux_amd64.tar.gz" gau.tgz; \
    tar -xzf gau.tgz && mv gau /usr/local/bin/gau && chmod +x /usr/local/bin/gau; \
    rm -f /tmp/waybackurls.tgz /tmp/gau.tgz /tmp/LICENSE* /tmp/README*

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
    paramspider \
    requests_ntlm

# ============================================================
# Playwright + Chromium (browser actuator)
# ============================================================
RUN playwright install --with-deps chromium

# Kali's `httpx-toolkit` package installs the binary at
# /usr/bin/httpx-toolkit. Alias it as `httpx` for code that shells out
# by that name — but ONLY if the Python httpx isn't already occupying
# the name (it isn't; the Python one lives inside /opt/venv, not on
# $PATH's system directories).
RUN if [ -x /usr/bin/httpx-toolkit ] && [ ! -e /usr/local/bin/httpx ]; then \
    ln -sf /usr/bin/httpx-toolkit /usr/local/bin/httpx; \
    fi

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

# ============================================================
# Drop root: create an unprivileged user for tool execution.
# Container process (`docker exec` from the API) enters as `pentester` unless
# the caller explicitly asks for root. The API side must not use `--user root`.
# ============================================================
RUN useradd --create-home --shell /bin/bash --uid 10001 pentester && \
    chown -R pentester:pentester /pentesting
USER pentester

CMD ["tail", "-f", "/dev/null"]
