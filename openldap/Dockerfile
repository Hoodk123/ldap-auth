FROM symas/openldap@sha256:ac6d6f4013777be7e75f4e870295ec9129ff4bb79ea98292bc38c21cecd21af5

USER root

RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    # Remove package manager cache — reduces attack surface
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

USER 1001
