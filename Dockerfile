FROM debian:buster-slim

COPY target/release/myeth-id /myeth-id

ENTRYPOINT ["/myeth-id"]
