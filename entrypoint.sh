#!/bin/bash

set -e

# Function for logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "Starting entrypoint script"

# Start the logging script
log "Starting log exports"

# Redirect all output to the logging script via VSOCK
exec > >(socat - VSOCK-CONNECT:3:8011) 2>&1

# Read and set APP_MODE from file
log "Reading /app/APP_MODE"
if [ -f /app/APP_MODE ]; then
    APP_MODE=""
    APP_MODE="$(cat /app/APP_MODE)" || { log "Failed to read /app/APP_MODE"; exit 1; }
    export APP_MODE
    log "Set APP_MODE=$APP_MODE from /app/APP_MODE"
else
    log "ERROR: /app/APP_MODE is missing. Please ensure the file exists and contains a valid mode (dev/preview/prod/custom)"
    exit 1
fi

log "Starting entrypoint script"
log "APP_MODE=$APP_MODE"
log "Kernel version: $(uname -r)"

# Configure loopback interface
log "Configuring loopback interface"
ip addr add 127.0.0.1/8 dev lo
ip link set dev lo up

# Function to send request and receive response via VSOCK
vsock_request() {
    local cid=$1
    local port=$2
    local request=$3

    response=$(python3 /app/vsock_helper.py "$cid" "$port" "$request")

    # Check if the response contains an error
    if echo "$response" | jq -e 'has("error")' > /dev/null; then
        error_message=$(echo "$response" | jq -r '.error')
        log "VSOCK request failed: $error_message"
        return 1
    fi

    echo "$response"
}

# Function to get AWS credentials
get_aws_credentials() {
    local cid=3
    local port=8003
    local request='{"request_type":"credentials","key_name":null}'

    vsock_request $cid $port "$request"
}

# Get AWS credentials
log "Fetching AWS credentials"
aws_creds=$(get_aws_credentials)
if [ -z "$aws_creds" ]; then
    log "Error: Failed to get AWS credentials"
    exit 1
fi

# Add error checking for jq parsing
if ! access_key_id=$(echo "$aws_creds" | jq -r '.response_value.AccessKeyId'); then
    log "Error: Failed to parse AccessKeyId from AWS credentials"
    log "AWS credentials response: $aws_creds"
    exit 1
fi
if ! secret_access_key=$(echo "$aws_creds" | jq -r '.response_value.SecretAccessKey'); then
    log "Error: Failed to parse SecretAccessKey from AWS credentials"
    exit 1
fi
if ! session_token=$(echo "$aws_creds" | jq -r '.response_value.Token'); then
    log "Error: Failed to parse Token from AWS credentials"
    exit 1
fi
if ! region=$(echo "$aws_creds" | jq -r '.response_value.Region'); then
    log "Error: Failed to parse Region from AWS credentials"
    exit 1
fi

log "AWS credentials retrieved and parsed successfully"

touch /app/libnsm.so
log "Created /app/libnsm.so"

# Start the opensecret
log "Starting opensecret..."
RUST_LOG_STYLE=never RUST_LOG=debug APP_MODE="$APP_MODE" /app/opensecret &

# Wait for the opensecret to start
log "Waiting for opensecret to start"
sleep 5

# Start socat to forward from vsock to the opensecret
log "Starting socat..."
socat VSOCK-LISTEN:5000,reuseaddr,fork TCP:0.0.0.0:3000
