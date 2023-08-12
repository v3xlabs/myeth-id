FROM debian:buster-slim

RUN apt-get update && apt-get install -y ca-certificates glibc libc6 libssl-dev && rm -rf /var/lib/apt/lists/*

COPY target/x86_64-unknown-linux-musl/release/myeth-id /bin/myeth-id

ENTRYPOINT ["myeth-id"]
