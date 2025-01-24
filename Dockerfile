####################################################################################################
## Builder
####################################################################################################
FROM docker.io/library/rust:latest AS builder

RUN update-ca-certificates

WORKDIR /app

COPY ./ .

# Build for the default target
RUN cargo build --release

####################################################################################################
## Final image
####################################################################################################
FROM enclave_base

# Install required packages including PostgreSQL client
RUN dnf update -y && \
    dnf install -y socat ca-certificates iproute python3 postgresql-libs jq && \
    dnf clean all

ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/app
ENV RUST_LOG_STYLE=never
ENV RUST_LOG=info

WORKDIR /app

# Copy kmstool_enclave_cli to bin directory
COPY --from=enclave_base /app/kmstool_enclave_cli /bin/kmstool_enclave_cli

# Copy our build
COPY --from=builder /app/target/release/opensecret /app/opensecret

# Copy the entrypoint script, traffic forwarder, and vsock helper programs
COPY entrypoint.sh /app/entrypoint.sh
COPY nitro-toolkit/traffic_forwarder.py /app/traffic_forwarder.py
COPY nitro-toolkit/vsock_helper.py /app/vsock_helper.py
RUN chmod +x /app/opensecret /app/entrypoint.sh

# Copy migrations folder
COPY --from=builder /app/migrations /app/migrations

# Add environment variables
ARG DATABASE_URL
ENV DATABASE_URL=${DATABASE_URL}
ARG OPENAI_API_KEY
ENV OPENAI_API_KEY=${OPENAI_API_KEY}
ARG APP_MODE
ENV APP_MODE=${APP_MODE:-dev}
ARG ENV_NAME
ENV ENV_NAME=${ENV_NAME}
ARG RESEND_API_KEY
ENV RESEND_API_KEY=${RESEND_API_KEY}

# Copy continuum-proxy
COPY continuum-proxy /app/continuum-proxy

# Expose the ports the app runs on
EXPOSE 3000 5432 8092

ENTRYPOINT ["/app/entrypoint.sh"]
