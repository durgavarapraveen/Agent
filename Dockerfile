# Stage 1: Build Go Binaries (Updated to Go 1.26)
FROM golang:1.26-alpine AS go-builder
ENV GOPATH=/go
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/tomnomnom/assetfinder@latest

# Stage 2: Heavy Base System (Cached permanently unless packages change)
FROM kalilinux/kali-rolling AS base
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-dev \
    build-essential curl wget git \
    nmap masscan sqlmap nikto hydra hashcat john aircrack-ng \
    dnsrecon dnsenum whois net-tools openssh-client imagemagick \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Stage 3: Python Dependencies
RUN pip3 install --break-system-packages --no-cache-dir \
    aiohttp pydantic python-dotenv requests fastapi uvicorn

# Stage 4: Copy Go Binaries from Stage 1
COPY --from=go-builder /go/bin/* /usr/local/bin/

WORKDIR /pentesting
RUN mkdir -p /pentesting/{reports,payloads,loot}

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD which nmap && which python3 && which curl

EXPOSE 9000 9001 9002 9003 9004
CMD ["tail", "-f", "/dev/null"]