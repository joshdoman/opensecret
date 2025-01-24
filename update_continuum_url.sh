#!/bin/bash

set -e

# Function for logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "Starting Continuum URL update script"

while true; do
    log "Running update check"

    # Fetch the manifest.toml
    manifest=$(curl -s https://cdn.confidential.cloud/continuum/v1/manifest.toml)

    # Extract the maaURL specifically from the attestationService.cpu.azureSEVSNP section
    maa_url=$(echo "$manifest" | awk '/^\[attestationService\.cpu\.azureSEVSNP\]/{flag=1; next} /^\[/{flag=0} flag && /^maaURL *=/{print $3; exit}' | tr -d '"')

    if [ -z "$maa_url" ]; then
        log "Error: Failed to extract maaURL from manifest"
        sleep 300  # Sleep for 5 minutes before trying again
        continue
    fi

    log "Extracted maaURL: $maa_url"

    # Extract the subdomain
    new_subdomain=$(echo "$maa_url" | awk -F[/:/.] '{print $4}')

    if [ -z "$new_subdomain" ]; then
        log "Error: Failed to extract subdomain from maaURL"
        sleep 300  # Sleep for 5 minutes before trying again
        continue
    fi

    log "Extracted subdomain: $new_subdomain"

    # Debug: Print the exact content of new_subdomain
    log "Debug: new_subdomain content: '${new_subdomain}'"

    # Ensure new_subdomain doesn't contain any unexpected characters
    new_subdomain=$(echo "$new_subdomain" | tr -cd '[:alnum:]')

    log "Debug: Cleaned new_subdomain: '${new_subdomain}'"

    # Check if the subdomain has changed
    vsock_proxy_file="/etc/nitro_enclaves/vsock-proxy.yaml"
    service_file="/etc/systemd/system/vsock-azure-continuum.service"
    current_subdomain=$(sudo grep -oP '(?<=address: )[^.]+(?=\.weu\.attest\.azure\.net)' "$vsock_proxy_file" | head -n1)

    log "Debug: Current subdomain: '${current_subdomain}'"

    if [ "$current_subdomain" != "$new_subdomain" ]; then
        # Update the vsock-proxy.yaml
        sed_command="s/\\(address: \\)[^.]*\\(\\.weu\\.attest\\.azure\\.net\\)/\\1${new_subdomain}\\2/"
        log "Debug: sed command for vsock_proxy_file: $sed_command"
        sudo sed -i "$sed_command" "$vsock_proxy_file"
        log "Updated $vsock_proxy_file"

        # Update the systemd service file
        sed_command="s/\\(ExecStart=\\/usr\\/bin\\/vsock-proxy 8009 \\)[^.]*\\(\\.weu\\.attest\\.azure\\.net\\)/\\1${new_subdomain}\\2/"
        log "Debug: sed command for service_file: $sed_command"
        sudo sed -i "$sed_command" "$service_file"
        log "Updated $service_file"

        # Reload systemd daemon
        sudo systemctl daemon-reload
        log "Reloaded systemd daemon"

        # Restart the nitro proxy service
        sudo systemctl restart nitro-enclaves-vsock-proxy.service
        log "Restarted nitro-enclaves-vsock-proxy.service"

        # Restart the Azure Continuum service
        sudo systemctl restart vsock-azure-continuum.service
        log "Restarted vsock-azure-continuum.service"

        # Find the EnclaveID of the previous running enclave
        ENCLAVES=$(nitro-cli describe-enclaves)
        log "Current enclaves: $ENCLAVES"
        OLD_ENCLAVE_ID=$(echo "$ENCLAVES" | jq -r '.[] | select(.EnclaveName == "opensecret") | .EnclaveID')
        
        if [ -n "$OLD_ENCLAVE_ID" ]; then
            log "Found old enclave ID: $OLD_ENCLAVE_ID"
            
            # Add a small delay before terminating the old enclave
            log "Waiting for 10 seconds before terminating old enclave"
            sleep 10
            
            # Attempt to terminate the old enclave
            log "Attempting to terminate old enclave with ID $OLD_ENCLAVE_ID"
            if nitro-cli terminate-enclave --enclave-id $OLD_ENCLAVE_ID; then
                log "Successfully terminated old enclave with ID $OLD_ENCLAVE_ID"
            else
                log "Failed to terminate old enclave with ID $OLD_ENCLAVE_ID. Please investigate."
                sleep 300  # Sleep for 5 minutes before trying again
                continue
            fi
        else
            log "No old enclave found running"
        fi

        # Wait for resources to be freed
        log "Waiting for 10 seconds before starting new enclave"
        sleep 10

        # Run the new enclave
        log "Starting new enclave"
        if nitro-cli run-enclave --eif-path ~/opensecret.eif --memory 16384 --cpu-count 4; then
            log "Enclave start command executed successfully"
            
            # Wait for the enclave to fully initialize (increase this if needed)
            log "Waiting for 30 seconds for the enclave to initialize"
            sleep 30
            
            # Check if the enclave is actually running
            if nitro-cli describe-enclaves | jq -e '.[] | select(.EnclaveName == "opensecret")' > /dev/null; then
                log "Enclave is running successfully"
            else
                log "Enclave failed to start properly. Please investigate."
                sleep 300  # Sleep for 5 minutes before trying again
                continue
            fi
        else
            log "Failed to start new enclave. Please investigate."
            sleep 300  # Sleep for 5 minutes before trying again
            continue
        fi
        
        # Wait for 10 seconds
        log "Waiting for 10 seconds before restarting socat proxy"
        sleep 10
        
        # Restart the socat proxy
        sudo systemctl restart socat-proxy.service
        log "Restarted socat-proxy.service"

        log "Enclave status after socat-proxy restart:"
        nitro-cli describe-enclaves

        log "Continuum URL update and enclave restart completed successfully"
    else
        log "No update needed. Current subdomain matches the new subdomain."
    fi

    log "Sleeping for 5 minutes before next check"
    sleep 300  # Sleep for 5 minutes (300 seconds)
done
