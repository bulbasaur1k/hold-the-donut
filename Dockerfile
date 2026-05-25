# Build + runtime image for hold-the-donut.
#
# Build a Linux x86_64 image for the server (from an Apple-Silicon host):
#   docker build --platform linux/amd64 -t donut .
#
# Run the server (cert-based carrier backend or direct QUIC):
#   docker run --rm -p 443:443/udp \
#     -v /etc/donut:/etc/donut donut
#
# Extract just the server binary for a systemd deploy (no Docker on the
# box):
#   id=$(docker create --platform linux/amd64 donut)
#   docker cp "$id:/usr/local/bin/donut-server" ./donut-server
#   docker rm "$id"

# ---- build stage ----
FROM rust:1-slim-bookworm AS build
# ring/quinn need a C toolchain + libc headers to compile/link; the slim
# rust image doesn't ship them.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# Drop the repo's toolchain pin so cargo uses the image's preinstalled
# toolchain (>= MSRV) instead of downloading the pinned channel — keeps
# the build offline-friendly on flaky networks.
RUN rm -f rust-toolchain.toml rust-toolchain \
    && cargo build --release -p donut-server -p donut-client

# ---- runtime stage ----
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/donut-server /usr/local/bin/donut-server
COPY --from=build /src/target/release/donut-client /usr/local/bin/donut-client
# 443/tcp: carrier backend behind a TLS front; 443/udp: direct QUIC/H3.
EXPOSE 443/tcp 443/udp
ENTRYPOINT ["/usr/local/bin/donut-server"]
CMD ["--config", "/etc/donut/server.json"]
