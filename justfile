# Load environment variables from .env file
set dotenv-load

# Set the container runtime (docker or podman)
container := "podman"

# Set the default recipe to list all available commands
default:
    @just --list

# Build the enclave base image
build-enclave-base:
    {{container}} build ./nitro-toolkit/enclave-base-image/ -t enclave_base

# Build Nitro binaries from enclave base image (NSM and KMS tools)
build-nitro-bins:
    mkdir -p nitro-bins
    {{container}} build -t nitro-bins -f nitro-toolkit/enclave-base-image/Dockerfile --target enclave_base .
    {{container}} create --name temp-nitro nitro-bins sh
    {{container}} cp temp-nitro:/app/libnsm.so nitro-bins/
    {{container}} cp temp-nitro:/app/kmstool_enclave_cli nitro-bins/
    {{container}} rm temp-nitro
    chmod +x nitro-bins/kmstool_enclave_cli

# Build the main Docker image for local
build-docker-local:
    {{container}} rmi opensecret:latest || true
    {{container}} build -t opensecret \
    --build-arg APP_MODE=local \
    .

### Credential Requester Commands ###

# Build the Credential Requester Docker image for development
build-credential-requester-docker:
    {{container}} rmi credential-requester:latest || true
    cd nitro-toolkit/credential_requester && \
    {{container}} build -t credential-requester .

# Save Credential Requester Docker image to a tar file for dev mode
save-credential-requester-docker-image-dev:
    rm -f build/credential-requester/dev/credential-requester.tar && \
    {{container}} save -o build/credential-requester/dev/credential-requester.tar credential-requester

# Save Credential Requester Docker image to a tar file for prod
save-credential-requester-docker-image-prod:
    rm -f build/credential-requester/prod/credential-requester.tar && \
    {{container}} save -o build/credential-requester/prod/credential-requester.tar credential-requester

# Save Credential Requester Docker image to a tar file for preview mode
save-credential-requester-docker-image-preview:
    rm -f build/credential-requester/preview/credential-requester.tar && \
    {{container}} save -o build/credential-requester/preview/credential-requester.tar credential-requester

# SCP the Credential Requester Docker image to the AWS parent instance (dev)
scp-credential-requester-to-aws-dev:
    scp -i $DEV_SSH_KEY build/credential-requester/dev/credential-requester.tar $DEV_SERVER:~/

# SCP the Docker image to the AWS parent instance (prod)
scp-credential-requester-to-aws-prod:
    scp -i $PROD_SSH_KEY build/credential-requester/prod/credential-requester.tar $PROD_SERVER:~/

# SCP the Credential Requester Docker image to the AWS parent instance (preview)
scp-credential-requester-to-aws-preview:
    scp -i $PREVIEW_SSH_KEY build/credential-requester/preview/credential-requester.tar $PREVIEW_SERVER:~/

# Load Credential Requester Docker image on AWS instance (dev)
load-credential-requester-docker-on-aws-dev:
    ssh -i $DEV_SSH_KEY $DEV_SERVER "docker load -i credential-requester.tar && docker tag localhost/credential-requester:latest credential-requester:latest"

# Load Credential Requester Docker image on AWS instance (prod)
load-credential-requester-docker-on-aws-prod:
    ssh -i $PROD_SSH_KEY $PROD_SERVER "docker load -i credential-requester.tar && docker tag localhost/credential-requester:latest credential-requester:latest"

# Load Credential Requester Docker image on AWS instance (preview)
load-credential-requester-docker-on-aws-preview:
    ssh -i $PREVIEW_SSH_KEY $PREVIEW_SERVER "docker load -i credential-requester.tar && docker tag localhost/credential-requester:latest credential-requester:latest"

# Run Credential Requester Docker image on AWS instance (dev)
run-credential-requester-docker-on-aws-dev:
    ssh -i $DEV_SSH_KEY $DEV_SERVER "docker run -d --restart always --name credential-requester --device=/dev/vsock:/dev/vsock -v /var/run/vsock:/var/run/vsock --privileged -e PORT=8003 credential-requester:latest"

# Run Credential Requester Docker image on AWS instance (prod)
run-credential-requester-docker-on-aws-prod:
    ssh -i $PROD_SSH_KEY $PROD_SERVER "docker run -d --restart always --name credential-requester --device=/dev/vsock:/dev/vsock -v /var/run/vsock:/var/run/vsock --privileged -e PORT=8003 credential-requester:latest"

# Run Credential Requester Docker image on AWS instance (preview)
run-credential-requester-docker-on-aws-preview:
    ssh -i $PREVIEW_SSH_KEY $PREVIEW_SERVER "docker run -d --restart always --name credential-requester --device=/dev/vsock:/dev/vsock -v /var/run/vsock:/var/run/vsock --privileged -e PORT=8003 credential-requester:latest"

### Logging Commands ###

# Build the Logging Docker image
build-logging-docker:
    {{container}} rmi enclave-logging:latest || true
    cd nitro-toolkit/logging && {{container}} build -t enclave-logging .

# Save Logging Docker image to a tar file (Dev)
save-logging-docker-image-dev:
    rm -f build/dev/logging/enclave-logging.tar && {{container}} save -o build/dev/logging/enclave-logging.tar enclave-logging

# Save Logging Docker image to a tar file (Prod)
save-logging-docker-image-prod:
    rm -f build/prod/logging/enclave-logging.tar && {{container}} save -o build/prod/logging/enclave-logging.tar enclave-logging

# Save Logging Docker image to a tar file (Preview)
save-logging-docker-image-preview:
    rm -f build/preview/logging/enclave-logging.tar && {{container}} save -o build/preview/logging/enclave-logging.tar enclave-logging

# SCP the Logging Docker image to the AWS parent instance (dev)
scp-logging-to-aws-dev:
    scp -i $DEV_SSH_KEY build/dev/logging/enclave-logging.tar $DEV_SERVER:~/

# SCP the Logging Docker image to the AWS parent instance (prod)
scp-logging-to-aws-prod:
    scp -i $PROD_SSH_KEY build/prod/logging/enclave-logging.tar $PROD_SERVER:~/

# SCP the Logging Docker image to the AWS parent instance (preview)
scp-logging-to-aws-preview:
    scp -i $PREVIEW_SSH_KEY build/preview/logging/enclave-logging.tar $PREVIEW_SERVER:~/

# Load Logging Docker image on AWS instance (dev)
load-logging-docker-on-aws-dev:
    ssh -i $DEV_SSH_KEY $DEV_SERVER "docker load -i enclave-logging.tar && docker tag localhost/enclave-logging:latest enclave-logging:latest"

# Load Logging Docker image on AWS instance (prod)
load-logging-docker-on-aws-prod:
    ssh -i $PROD_SSH_KEY $PROD_SERVER "docker load -i enclave-logging.tar && docker tag localhost/enclave-logging:latest enclave-logging:latest"

# Load Logging Docker image on AWS instance (preview)
load-logging-docker-on-aws-preview:
    ssh -i $PREVIEW_SSH_KEY $PREVIEW_SERVER "docker load -i enclave-logging.tar && docker tag localhost/enclave-logging:latest enclave-logging:latest"

# Run Logging Docker image on AWS instance (dev)
run-logging-docker-on-aws-dev:
    ssh -i $DEV_SSH_KEY $DEV_SERVER "docker run -d --restart always --name enclave-logging --device=/dev/vsock:/dev/vsock -v /var/run/vsock:/var/run/vsock --privileged -e VSOCK_PORT=8011 -e LOG_GROUP=/aws/nitro-enclaves/maple-enclave-dev -e LOG_STREAM=enclave-logs-dev -e AWS_REGION=us-east-2 enclave-logging:latest"

# Run Logging Docker image on AWS instance (prod)
run-logging-docker-on-aws-prod:
    ssh -i $PROD_SSH_KEY $PROD_SERVER "docker run -d --restart always --name enclave-logging --device=/dev/vsock:/dev/vsock -v /var/run/vsock:/var/run/vsock --privileged -e VSOCK_PORT=8011 -e LOG_GROUP=/aws/nitro-enclaves/maple-enclave-prod -e LOG_STREAM=enclave-logs-prod -e AWS_REGION=us-east-2 enclave-logging:latest"

# Run Logging Docker image on AWS instance (preview)
run-logging-docker-on-aws-preview:
    ssh -i $PREVIEW_SSH_KEY $PREVIEW_SERVER "docker run -d --restart always --name enclave-logging --device=/dev/vsock:/dev/vsock -v /var/run/vsock:/var/run/vsock --privileged -e VSOCK_PORT=8011 -e LOG_GROUP=/aws/nitro-enclaves/maple-enclave-preview -e LOG_STREAM=enclave-logs-preview -e AWS_REGION=us-east-2 enclave-logging:latest"

# Build and deploy logging for dev
build-and-deploy-logging-dev: build-logging-docker save-logging-docker-image-dev scp-logging-to-aws-dev load-logging-docker-on-aws-dev run-logging-docker-on-aws-dev

# Build and deploy logging for prod
build-and-deploy-logging-prod: build-logging-docker save-logging-docker-image-prod scp-logging-to-aws-prod load-logging-docker-on-aws-prod run-logging-docker-on-aws-prod

# Build and deploy logging for preview
build-and-deploy-logging-preview: build-logging-docker save-logging-docker-image-preview scp-logging-to-aws-preview load-logging-docker-on-aws-preview run-logging-docker-on-aws-preview

### Database Commands ###

# Setup diesel CLI (first-time setup)
diesel-setup:
    diesel setup

# Generate a new migration
diesel-migration-generate name:
    diesel migration generate {{name}}

# Run migrations locally
diesel-migration-run-local:
    diesel migration run

# Run migrations on development
diesel-migration-run-dev:
    diesel migration run --database-url $DEV_DATABASE_URL

# Run migrations on production
diesel-migration-run-prod:
    diesel migration run --database-url $PROD_DATABASE_URL

# Run migrations on preview
diesel-migration-run-preview:
    diesel migration run --database-url $PREVIEW_DATABASE_URL


### Continuum Proxy Commands ###

# Update continuum-proxy
update-continuum-proxy:
    containerID=$({{container}} create --platform linux/arm64 ghcr.io/edgelesssys/privatemode/privatemode-proxy:v1.7.1-0.20250211140643-2dd126d4748c) && \
    {{container}} cp "${containerID}":/bin/privatemode-proxy ./continuum-proxy && \
    {{container}} rm "${containerID}"

### Enclave Management ###

# Terminate the running enclave (dev)
terminate-enclave-dev:
    ssh -i $DEV_SSH_KEY $DEV_SERVER 'bash -c "\
    ENCLAVE_ID=\$(nitro-cli describe-enclaves | jq -r \".[0].EnclaveID\") && \
    if [ ! -z \"\$ENCLAVE_ID\" ]; then \
        echo \"Terminating enclave with ID: \$ENCLAVE_ID\" && \
        nitro-cli terminate-enclave --enclave-id \$ENCLAVE_ID; \
    else \
        echo \"No running enclave found.\"; \
    fi"'

# Terminate the running enclave (prod)
terminate-enclave-prod:
    ssh -i $PROD_SSH_KEY $PROD_SERVER 'bash -c "\
    ENCLAVE_ID=\$(nitro-cli describe-enclaves | jq -r \".[0].EnclaveID\") && \
    if [ ! -z \"\$ENCLAVE_ID\" ]; then \
        echo \"Terminating enclave with ID: \$ENCLAVE_ID\" && \
        nitro-cli terminate-enclave --enclave-id \$ENCLAVE_ID; \
    else \
        echo \"No running enclave found.\"; \
    fi"'

# Terminate the running enclave (preview)
terminate-enclave-preview:
    ssh -i $PREVIEW_SSH_KEY $PREVIEW_SERVER 'bash -c "\
    ENCLAVE_ID=\$(nitro-cli describe-enclaves | jq -r \".[0].EnclaveID\") && \
    if [ ! -z \"\$ENCLAVE_ID\" ]; then \
        echo \"Terminating enclave with ID: \$ENCLAVE_ID\" && \
        nitro-cli terminate-enclave --enclave-id \$ENCLAVE_ID; \
    else \
        echo \"No running enclave found.\"; \
    fi"'

# Restart socat-proxy service (dev)
restart-socat-dev:
    ssh -i $DEV_SSH_KEY $DEV_SERVER "sudo systemctl restart socat-proxy.service"

# Restart socat-proxy service (prod)
restart-socat-prod:
    ssh -i $PROD_SSH_KEY $PROD_SERVER "sudo systemctl restart socat-proxy.service"
#
# Restart socat-proxy service (preview)
restart-socat-preview:
    ssh -i $PREVIEW_SSH_KEY $PREVIEW_SERVER "sudo systemctl restart socat-proxy.service"

# Run the staged dev environment
run-stage-dev: terminate-enclave-dev run-eif-dev restart-socat-dev

# Run the staged prod environment
run-stage-prod: terminate-enclave-prod run-eif-prod restart-socat-prod

# Run the staged preview environment
run-stage-preview: terminate-enclave-preview run-eif-preview restart-socat-preview

### EIF Building ###

# Build the EIF using Nix
build-eif:
    nix build .?submodules=1#eif
    echo "EIF build completed. PCR:"
    cat result/pcr.json

# Build EIF for development environment
build-eif-dev:
    nix build .?submodules=1#eif-dev
    echo "EIF build completed. PCR:"
    cat result/pcr.json

# Build EIF for production environment
build-eif-prod:
    nix build .?submodules=1#eif-prod
    echo "EIF build completed. PCR:"
    cat result/pcr.json

# Build EIF for preview environment
build-eif-preview:
    nix build .?submodules=1#eif-preview
    echo "EIF build completed. PCR:"
    cat result/pcr.json

# Build EIF with custom environment variables
build-eif-custom env_vars:
    #!/usr/bin/env bash
    eval "{{env_vars}}" nix build .?submodules=1#eif
    echo "EIF build completed. PCR:"
    cat result/pcr.json

# Build EIF for development environment
copy-pcr-dev:
    nix build .?submodules=1#eif-dev
    echo "EIF build completed. PCR:"
    cat result/pcr.json
    cp -f result/pcr.json ./pcrDev.json

# Build EIF for production environment
copy-pcr-prod:
    nix build .?submodules=1#eif-prod
    echo "EIF build completed. PCR:"
    cat result/pcr.json
    cp -f result/pcr.json ./pcrProd.json

# Sign and append PCR measurements for dev environment
append-pcr-dev:
    #!/usr/bin/env bash
    set -e
    
    # Check for required environment variable
    if [ -z "${SIGNING_PRIVATE_KEY}" ]; then
        echo "❌ Error: SIGNING_PRIVATE_KEY environment variable is not set"
        echo "Please set it with the base64-encoded private key:"
        echo "export SIGNING_PRIVATE_KEY='...'"
        exit 1
    fi
    
    # Initialize empty history file if it doesn't exist
    if [ ! -f "./pcrDevHistory.json" ]; then
        echo "[]" > ./pcrDevHistory.json
    fi
    
    # Get current PCR values
    PCR_CONTENT=$(cat ./pcrDev.json | jq -c '.')
    CURRENT_PCR0=$(echo $PCR_CONTENT | jq -r '.PCR0')
    
    # Check if this PCR0 already exists in the history
    HISTORY=$(cat ./pcrDevHistory.json)
    PCR0_EXISTS=$(echo $HISTORY | jq --arg pcr0 "$CURRENT_PCR0" 'map(select(.PCR0 == $pcr0)) | length')
    
    if [ "$PCR0_EXISTS" -gt "0" ]; then
        echo "⚠️  PCR0 value already exists in pcrDevHistory.json"
        echo "    Skipping append operation to avoid duplicates."
        exit 0
    fi
    
    # Prepare the entry with timestamp
    TIMESTAMP=$(date +%s)
    ENTRY=$(echo $PCR_CONTENT | jq --arg ts "$TIMESTAMP" '. + {"timestamp": ($ts | tonumber)}')
    
    # Create temporary private key file from the environment variable
    TEMP_KEY_FILE=$(mktemp)
    echo "${SIGNING_PRIVATE_KEY}" | base64 --decode > "$TEMP_KEY_FILE"
    
    # Sign the entry using the private key
    SIGNATURE=$(echo -n "$ENTRY" | openssl dgst -sha384 -sign "$TEMP_KEY_FILE" -keyform PEM | base64 -w 0)
    
    # Remove temporary key file
    rm -f "$TEMP_KEY_FILE"
    
    # Add signature to the entry
    SIGNED_ENTRY=$(echo $ENTRY | jq --arg sig "$SIGNATURE" '. + {"signature": $sig}')
    
    # Append to history file
    echo $HISTORY | jq --argjson entry "$SIGNED_ENTRY" '. + [$entry]' > ./pcrDevHistory.json
    
    echo "✅ Successfully appended signed PCR entry to pcrDevHistory.json"

# Sign and append PCR measurements for prod environment
append-pcr-prod:
    #!/usr/bin/env bash
    set -e
    
    # Check for required environment variable
    if [ -z "${SIGNING_PRIVATE_KEY}" ]; then
        echo "❌ Error: SIGNING_PRIVATE_KEY environment variable is not set"
        echo "Please set it with the base64-encoded private key:"
        echo "export SIGNING_PRIVATE_KEY='...'"
        exit 1
    fi
    
    # Initialize empty history file if it doesn't exist
    if [ ! -f "./pcrProdHistory.json" ]; then
        echo "[]" > ./pcrProdHistory.json
    fi
    
    # Get current PCR values
    PCR_CONTENT=$(cat ./pcrProd.json | jq -c '.')
    CURRENT_PCR0=$(echo $PCR_CONTENT | jq -r '.PCR0')
    
    # Check if this PCR0 already exists in the history
    HISTORY=$(cat ./pcrProdHistory.json)
    PCR0_EXISTS=$(echo $HISTORY | jq --arg pcr0 "$CURRENT_PCR0" 'map(select(.PCR0 == $pcr0)) | length')
    
    if [ "$PCR0_EXISTS" -gt "0" ]; then
        echo "⚠️  PCR0 value already exists in pcrProdHistory.json"
        echo "    Skipping append operation to avoid duplicates."
        exit 0
    fi
    
    # Prepare the entry with timestamp
    TIMESTAMP=$(date +%s)
    ENTRY=$(echo $PCR_CONTENT | jq --arg ts "$TIMESTAMP" '. + {"timestamp": ($ts | tonumber)}')
    
    # Create temporary private key file from the environment variable
    TEMP_KEY_FILE=$(mktemp)
    echo "${SIGNING_PRIVATE_KEY}" | base64 --decode > "$TEMP_KEY_FILE"
    
    # Sign the entry using the private key
    SIGNATURE=$(echo -n "$ENTRY" | openssl dgst -sha384 -sign "$TEMP_KEY_FILE" -keyform PEM | base64 -w 0)
    
    # Remove temporary key file
    rm -f "$TEMP_KEY_FILE"
    
    # Add signature to the entry
    SIGNED_ENTRY=$(echo $ENTRY | jq --arg sig "$SIGNATURE" '. + {"signature": $sig}')
    
    # Append to history file
    echo $HISTORY | jq --argjson entry "$SIGNED_ENTRY" '. + [$entry]' > ./pcrProdHistory.json
    
    echo "✅ Successfully appended signed PCR entry to pcrProdHistory.json"

# Update PCR dev with signature and append to history
update-pcr-dev:
    just copy-pcr-dev
    just append-pcr-dev
    echo "✅ PCR dev values updated and history appended"

# Update PCR prod with signature and append to history
update-pcr-prod:
    just copy-pcr-prod
    just append-pcr-prod
    echo "✅ PCR prod values updated and history appended"


# Generate a key pair for PCR signing and output to terminal (no files created)
generate-pcr-keys:
    #!/usr/bin/env bash
    set -e
    
    # Generate private key (using secp384r1/P-384 curve for ECDSA with SHA-384)
    TEMP_PRIVATE_KEY=$(mktemp)
    TEMP_PUBLIC_KEY=$(mktemp)
    TEMP_PUBLIC_KEY_DER=$(mktemp)
    
    # Generate the keys
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out "$TEMP_PRIVATE_KEY" 2>/dev/null
    
    # Extract public key in PEM format
    openssl ec -in "$TEMP_PRIVATE_KEY" -pubout -out "$TEMP_PUBLIC_KEY" 2>/dev/null
    
    # Extract public key in DER format
    openssl ec -in "$TEMP_PRIVATE_KEY" -pubout -outform DER -out "$TEMP_PUBLIC_KEY_DER" 2>/dev/null
    
    # Base64 encode the keys
    PRIVATE_KEY_BASE64=$(base64 "$TEMP_PRIVATE_KEY" | tr -d '\n')
    PUBLIC_KEY_BASE64=$(base64 "$TEMP_PUBLIC_KEY" | tr -d '\n')
    PUBLIC_KEY_DER_BASE64=$(base64 "$TEMP_PUBLIC_KEY_DER" | tr -d '\n')
    
    # Output the keys (formatted for readability)
    echo "===== PRIVATE KEY (PEM) ====="
    cat "$TEMP_PRIVATE_KEY"
    echo ""
    
    echo "===== PUBLIC KEY (PEM) ====="
    cat "$TEMP_PUBLIC_KEY"
    echo ""
    
    echo "===== PRIVATE KEY (BASE64) ====="
    echo "$PRIVATE_KEY_BASE64"
    echo ""
    
    echo "===== PUBLIC KEY (PEM BASE64) ====="
    echo "$PUBLIC_KEY_BASE64"
    echo ""
    
    echo "===== PUBLIC KEY (DER BASE64 - FOR FRONTEND) ====="
    echo "$PUBLIC_KEY_DER_BASE64"
    echo ""
    
    echo "===== FOR ENVIRONMENT VARIABLES ====="
    echo "export SIGNING_PRIVATE_KEY='$PRIVATE_KEY_BASE64'"
    echo "export SIGNING_PUBLIC_KEY='$PUBLIC_KEY_BASE64'"
    echo ""
    
    echo "===== FOR VERIFICATION ====="
    echo "just verify-pcr-history dev"
    echo ""
    
    # Clean up temporary files
    rm "$TEMP_PRIVATE_KEY" "$TEMP_PUBLIC_KEY" "$TEMP_PUBLIC_KEY_DER"

# Verify signatures in a PCR history file using the SIGNING_PUBLIC_KEY environment variable
verify-pcr-history env:
    #!/usr/bin/env bash
    set -e
    
    # Check for required environment variable
    if [ -z "${SIGNING_PUBLIC_KEY}" ]; then
        echo "❌ Error: SIGNING_PUBLIC_KEY environment variable is not set"
        echo "Please set it with the base64-encoded public key:"
        echo "export SIGNING_PUBLIC_KEY='...'"
        exit 1
    fi
    
    HISTORY_FILE="pcr{{env}}History.json"
    
    if [ ! -f "./$HISTORY_FILE" ]; then
        echo "❌ $HISTORY_FILE doesn't exist"
        exit 1
    fi
    
    # Create a temporary file for the public key from environment variable
    TEMP_PUBLIC_KEY=$(mktemp)
    echo "${SIGNING_PUBLIC_KEY}" | base64 --decode > "$TEMP_PUBLIC_KEY"
    
    echo "Verifying signatures in $HISTORY_FILE..."
    
    # Process each entry in the history file
    ENTRIES=$(cat $HISTORY_FILE | jq -c '.[]')
    COUNT=0
    VALID=0
    
    while IFS= read -r ENTRY; do
        COUNT=$((COUNT + 1))
        
        # Extract data from entry
        PCR_DATA=$(echo $ENTRY | jq 'del(.signature)')
        SIGNATURE=$(echo $ENTRY | jq -r '.signature')
        PCR0=$(echo $ENTRY | jq -r '.PCR0')
        TIMESTAMP=$(echo $ENTRY | jq -r '.timestamp')
        
        # Convert timestamp to human-readable format
        # Using date --date or date -d instead of date -r for better compatibility
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS date command
            TIMESTAMP_HUMAN=$(date -r $TIMESTAMP)
        else
            # Linux date command
            TIMESTAMP_HUMAN=$(date -d "@$TIMESTAMP")
        fi
        
        echo "Entry $COUNT:"
        echo "  Timestamp: $TIMESTAMP_HUMAN (unix: $TIMESTAMP)"
        echo "  PCR0: $PCR0"
        
        # Save signature as binary
        TEMP_SIG_FILE=$(mktemp)
        echo $SIGNATURE | base64 -d > "$TEMP_SIG_FILE"
        
        # Verify signature
        if echo -n "$PCR_DATA" | openssl dgst -sha384 -verify "$TEMP_PUBLIC_KEY" -signature "$TEMP_SIG_FILE" > /dev/null 2>&1; then
            echo "  ✅ Signature: Valid"
            VALID=$((VALID + 1))
        else
            echo "  ❌ Signature: Invalid"
        fi
        
        # Remove temporary signature file
        rm -f "$TEMP_SIG_FILE"
        echo ""
    done <<< "$ENTRIES"
    
    # Clean up
    rm -f "$TEMP_PUBLIC_KEY"
    
    echo "Verification complete: $VALID/$COUNT signatures valid"
    
    if [ $VALID -eq $COUNT ]; then
        echo "✅ All signatures in $HISTORY_FILE are valid"
        exit 0
    else
        echo "❌ Some signatures in $HISTORY_FILE are invalid"
        exit 1
    fi

# Internal function for PCR verification
_verify-pcr-internal env pcr_file:
    #!/usr/bin/env bash
    if [ ! -f "./{{pcr_file}}" ]; then
        echo "No {{pcr_file}} found. Building {{env}} EIF first..."
        just build-eif-{{env}}
        exit 0
    fi
    
    if [ ! -f result/pcr.json ]; then
        echo "No result/pcr.json found. Building {{env}} EIF first..."
        just build-eif-{{env}}
    fi
    
    if diff -q "./{{pcr_file}}" result/pcr.json > /dev/null; then
        echo "✅ {{env}} PCR values match!"
    else
        echo "❌ {{env}} PCR values do not match!"
        echo "Expected (./{{pcr_file}}):"
        cat "./{{pcr_file}}"
        echo "Got (result/pcr.json):"
        cat result/pcr.json
        exit 1
    fi

# Verify PCR values for dev environment
verify-pcr-dev:
    just _verify-pcr-internal dev pcrDev.json

# Verify PCR values for prod environment
verify-pcr-prod:
    just _verify-pcr-internal prod pcrProd.json

# Verify PCR values for preview environment
verify-pcr-preview:
    just _verify-pcr-internal preview pcrPreview.json

# Verify PCR values for custom environment
verify-pcr-custom:
    #!/usr/bin/env bash
    if [ ! -f ./pcrCustom.json ]; then
        echo "No pcrCustom.json found. Please run build-eif-custom first"
        exit 1
    fi
    
    if [ ! -f result/pcr.json ]; then
        echo "No result/pcr.json found. Please rebuild with the same environment variables"
        exit 1
    fi
    
    if diff -q ./pcrCustom.json result/pcr.json > /dev/null; then
        echo "✅ Custom PCR values match!"
    else
        echo "❌ Custom PCR values do not match!"
        echo "Expected (./pcrCustom.json):"
        cat ./pcrCustom.json
        echo "Got (result/pcr.json):"
        cat result/pcr.json
        exit 1
    fi

# SCP the Nix-built EIF to AWS parent instance (dev)
scp-eif-to-aws-dev:
    ssh -i $DEV_SSH_KEY $DEV_SERVER "rm -f ~/opensecret.eif"
    scp -i $DEV_SSH_KEY result/image.eif $DEV_SERVER:~/opensecret.eif

# SCP the Nix-built EIF to AWS parent instance (prod)
scp-eif-to-aws-prod:
    ssh -i $PROD_SSH_KEY $PROD_SERVER "rm -f ~/opensecret.eif"
    scp -i $PROD_SSH_KEY result/image.eif $PROD_SERVER:~/opensecret.eif

# SCP the Nix-built EIF to AWS parent instance (preview)
scp-eif-to-aws-preview:
    ssh -i $PREVIEW_SSH_KEY $PREVIEW_SERVER "rm -f ~/opensecret.eif"
    scp -i $PREVIEW_SSH_KEY result/image.eif $PREVIEW_SERVER:~/opensecret.eif

# Stage to dev environment without debug mode (using Nix-built EIF)
stage-dev-nix: build-eif-dev scp-eif-to-aws-dev

# Stage to prod environment without debug mode (using Nix-built EIF)
stage-prod-nix: build-eif-prod scp-eif-to-aws-prod

# Stage to preview environment without debug mode (using Nix-built EIF)
stage-preview-nix: build-eif-preview scp-eif-to-aws-preview

# Run EIF file on AWS (dev)
run-eif-dev:
    ssh -i $DEV_SSH_KEY $DEV_SERVER "nitro-cli run-enclave --eif-path opensecret.eif --memory 16384 --cpu-count 4"

# Run EIF file on AWS (prod)
run-eif-prod:
    ssh -i $PROD_SSH_KEY $PROD_SERVER "nitro-cli run-enclave --eif-path opensecret.eif --memory 16384 --cpu-count 4"

# Run EIF file on AWS (preview)
run-eif-preview:
    ssh -i $PREVIEW_SSH_KEY $PREVIEW_SERVER "nitro-cli run-enclave --eif-path opensecret.eif --memory 16384 --cpu-count 4"

# Run EIF file in debug mode (preview)
run-eif-debug-preview:
    ssh -i $PREVIEW_SSH_KEY $PREVIEW_SERVER "nitro-cli run-enclave --eif-path opensecret.eif --memory 16384 --cpu-count 4 --debug-mode"

# Run EIF file in debug mode (dev)
run-eif-debug-dev:
    ssh -i $DEV_SSH_KEY $DEV_SERVER "nitro-cli run-enclave --eif-path opensecret.eif --memory 16384 --cpu-count 4 --debug-mode"

# Run EIF file in debug mode (prod)
run-eif-debug-prod:
    ssh -i $PROD_SSH_KEY $PROD_SERVER "nitro-cli run-enclave --eif-path opensecret.eif --memory 16384 --cpu-count 4 --debug-mode"

# View console logs in debug mode (dev)
view-console-logs-dev:
    ssh -i $DEV_SSH_KEY $DEV_SERVER "export ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID') && nitro-cli console --enclave-id $ENCLAVE_ID"

# View console logs in debug mode (prod)
view-console-logs-prod:
    ssh -i $PROD_SSH_KEY $PROD_SERVER "export ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID') && nitro-cli console --enclave-id $ENCLAVE_ID"

# View console logs in debug mode (preview)
view-console-logs-preview:
    ssh -i $PREVIEW_SSH_KEY $PREVIEW_SERVER "export ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID') && nitro-cli console --enclave-id $ENCLAVE_ID"

# Deploy to dev environment without debug mode (using Nix-built EIF)
deploy-dev-nix: build-eif-dev verify-pcr-dev scp-eif-to-aws-dev
    @echo "EIF copied to server. Please review the PCR values and press Enter to continue with termination and deployment..."
    @read -p ""
    just terminate-enclave-dev run-eif-dev restart-socat-dev

# Deploy to prod environment without debug mode (using Nix-built EIF)
deploy-prod-nix: build-eif-prod verify-pcr-prod scp-eif-to-aws-prod
    @echo "EIF copied to production server. Please review the PCR values and press Enter to continue with termination and deployment..."
    @read -p ""
    just terminate-enclave-prod run-eif-prod restart-socat-prod

# Deploy to preview environment without debug mode (using Nix-built EIF)
deploy-preview-nix: build-eif-preview verify-pcr-preview scp-eif-to-aws-preview
    @echo "EIF copied to preview server. Please review the PCR values and press Enter to continue with termination and deployment..."
    @read -p ""
    just terminate-enclave-preview run-eif-preview restart-socat-preview

# Clean EIF build artifacts
clean-eif:
    rm -f result
