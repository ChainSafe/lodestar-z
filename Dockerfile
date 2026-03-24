# lodestar-z beacon node — multi-stage Zig build
FROM ubuntu:22.04 AS builder

# Install Zig 0.16
RUN apt-get update && apt-get install -y curl xz-utils && \
    curl -L https://ziglang.org/builds/zig-linux-x86_64-0.16.0-dev.2915+065c6e794.tar.xz | \
    tar -xJ -C /opt && \
    ln -s /opt/zig-linux-x86_64-0.16.0-dev.2915+065c6e794/zig /usr/local/bin/zig

# Install C deps needed for lsquic/boringssl
RUN apt-get install -y build-essential cmake

WORKDIR /build
COPY . .

# Build release binary
RUN zig build -Doptimize=ReleaseSafe

# Runtime stage — minimal image
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/zig-out/bin/lodestar-z /usr/local/bin/lodestar-z

# Default ports: REST API 5052, P2P 9000, Metrics 8008
EXPOSE 5052 9000/tcp 9000/udp 8008

ENTRYPOINT ["lodestar-z"]
CMD ["--network", "minimal", "--api-port", "5052", "--p2p-port", "9000"]
