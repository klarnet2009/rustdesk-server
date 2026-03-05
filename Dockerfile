FROM rust:slim-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libsqlite3-dev \
    build-essential \
    file \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

RUN cargo build --release --jobs 2 --bin hbbs --bin hbbr

# ---- Runtime ----
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libsqlite3-0 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/hbbs /usr/bin/hbbs
COPY --from=builder /build/target/release/hbbr /usr/bin/hbbr

WORKDIR /root
ENV HOME=/root

EXPOSE 21115 21116 21116/udp 21117 21118 21119
