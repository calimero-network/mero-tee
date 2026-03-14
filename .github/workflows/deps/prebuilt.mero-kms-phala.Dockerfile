# syntax=docker/dockerfile:1

FROM ubuntu:24.04

LABEL org.opencontainers.image.description="Phala KMS for merod TEE nodes" \
    org.opencontainers.image.licenses="MIT OR Apache-2.0" \
    org.opencontainers.image.authors="Calimero Limited <info@calimero.network>" \
    org.opencontainers.image.source="https://github.com/calimero-network/mero-tee" \
    org.opencontainers.image.url="https://calimero.network"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG UID=10001
RUN useradd \
    --home-dir "/user" \
    --create-home \
    --shell "/sbin/nologin" \
    --uid "${UID}" \
    user

ARG TARGETARCH

COPY bin/${TARGETARCH}/mero-kms-phala /usr/local/bin/
RUN chmod +x /usr/local/bin/mero-kms-phala

ARG KMS_IMAGE_PROFILE=locked-read-only
LABEL io.calimero.kms_profile="${KMS_IMAGE_PROFILE}"
RUN mkdir -p /etc/mero-kms \
    && printf '%s\n' "${KMS_IMAGE_PROFILE}" > /etc/mero-kms/image-profile \
    && chmod 0444 /etc/mero-kms/image-profile
ENV KMS_IMAGE_PROFILE="${KMS_IMAGE_PROFILE}"

USER user

ENV LISTEN_ADDR=0.0.0.0:8080
ENV DSTACK_SOCKET_PATH=/var/run/dstack.sock
ENV ACCEPT_MOCK_ATTESTATION=false
ENV RUST_LOG=info

VOLUME /data
EXPOSE 8080

CMD ["mero-kms-phala"]
