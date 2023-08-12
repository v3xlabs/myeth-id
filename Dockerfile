FROM debian:buster-stable

RUN apt-get update && apt-get install -y ca-certificates glibc libc6 libssl-dev && rm -rf /var/lib/apt/lists/*

COPY target/release/myeth-id /bin/myeth-id

ENTRYPOINT ["myeth-id"]
