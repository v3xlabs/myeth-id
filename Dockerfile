FROM alpine:latest

RUN apk update --quiet \
&& apk add -q --no-cache libgcc tini curl

COPY target/release/myeth-id /bin/myeth-id
RUN ln -s /bin/myeth-id /myeth-id

ENTRYPOINT ["myeth-id"]
