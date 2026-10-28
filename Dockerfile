FROM rust:1.90-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.toml
COPY src src
COPY migrations migrations
RUN cargo build --release --bin scried-backend

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home scried
WORKDIR /app
COPY --from=builder /app/target/release/scried-backend /usr/local/bin/scried-backend
COPY --from=builder /app/migrations /app/migrations
RUN mkdir -p /var/lib/scried/private && chown -R scried:scried /var/lib/scried
USER scried
ENV HOST=0.0.0.0 PORT=8080 PRIVATE_STORAGE_DIR=/var/lib/scried/private
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/scried-backend"]
