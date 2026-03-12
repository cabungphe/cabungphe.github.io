FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y gcc socat libc6-dev && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m ezhik
WORKDIR /home/ezhik

COPY fantiky_shop.c .
COPY docker-entrypoint.sh .

RUN gcc fantiky_shop.c -o fantiky_shop \
    -O0 \
    -fno-stack-protector \
    -U_FORTIFY_SOURCE \
    -fPIE -pie \
    -Wl,-z,relro,-z,now

RUN chown -R root:ezhik /home/ezhik && \
    chmod 750 /home/ezhik/fantiky_shop

EXPOSE 5364

RUN chmod +x docker-entrypoint.sh

ENTRYPOINT ["/bin/sh", "./docker-entrypoint.sh"]