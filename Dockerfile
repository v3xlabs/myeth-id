FROM alpine:latest

RUN apk update --quiet \
&& apk add -q --no-cache libgcc curl

COPY target/release/myeth-id /myeth-id

ENTRYPOINT ["/myeth-id"]
