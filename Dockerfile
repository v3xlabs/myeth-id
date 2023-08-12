FROM debian:buster-slim

RUN apt-get update && apt-get install -y ca-certificates libc6 libssl-dev && rm -rf /var/lib/apt/lists/*

COPY target/release/myeth-id /myeth-id

ENTRYPOINT ["/myeth-id"]
