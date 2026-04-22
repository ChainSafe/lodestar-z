FROM ubuntu:24.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        libstdc++6 \
        nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /

RUN mkdir -p /packages/cli/bin
COPY docker/kurtosis/package.json /packages/cli/package.json
COPY docker/kurtosis/lodestar-wrapper.js /packages/cli/bin/lodestar
COPY zig-out/bin/lodestar-z /usr/local/bin/lodestar-z

RUN chmod +x /usr/local/bin/lodestar-z /packages/cli/bin/lodestar

EXPOSE 4000 8008 8080 9000/tcp 9000/udp

ENTRYPOINT ["node", "./packages/cli/bin/lodestar"]
CMD ["beacon", "--help"]
