FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends slapd ldap-utils ca-certificates python3 python3-ldap3 && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /certs /schema/custom

COPY scripts/entrypoint.sh /entrypoint.sh
COPY scripts/ldap-syncctl.py /usr/local/bin/ldap-syncctl.py

COPY schema/custom /schema/custom

RUN chmod +x /entrypoint.sh /usr/local/bin/ldap-syncctl.py

EXPOSE 389 636

ENTRYPOINT ["/entrypoint.sh"]
