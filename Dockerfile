# lodestar-z beacon node
# Build with: docker build --build-arg ZIG_PATH=/path/to/zig -t lodestar-z:local .
# Or simpler: use the build script below

FROM ubuntu:22.04

# Install deps
RUN apt-get update && apt-get install -y build-essential cmake ca-certificates libstdc++6 && \
    rm -rf /var/lib/apt/lists/*

# Copy pre-built binary (build outside Docker with zig build -Doptimize=ReleaseSafe)
COPY zig-out/bin/lodestar-z /usr/local/bin/lodestar-z
RUN chmod +x /usr/local/bin/lodestar-z

# Default ports: REST API 5052, P2P 9000, Metrics 8008
EXPOSE 5052 9000/tcp 9000/udp 8008

ENTRYPOINT ["lodestar-z"]
CMD ["--network", "minimal", "--api-port", "5052", "--p2p-port", "9000"]
