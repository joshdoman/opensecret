# Deploy on Nitro

## Log into AWS CLI 

This should be after creating an IAM profile with admin access. 

For the first time: 
```
aws configure sso
```

For logging in to an existing profile (replace with your own):
```
aws sso login --profile AdministratorAccess-1111
```

## Create an SSH Keypair for logging into the machine:

Read up on the [docs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/create-key-pairs.html). Either import existing or create a new one.

To ge the public key of an existing `.pem` file:

```
ssh-keygen -y -f ~/.ssh/your_ssh.pem 
```

## Create a container that is nitro compatible

Read up on the [docs](https://docs.aws.amazon.com/enclaves/latest/user/getting-started.html) if needed.

Use this ec2 command:


Replace `AWS_PROFILE` with your CLI access name. Ex. `AdministratorAccess-1111`
Replace `KEY_NAME` with the uploaded ssh key. Ex. `tony_dev_ssh`

```
aws ec2 run-instances \
--image-id ami-067df2907035c28c2 \
--count 1 \
--instance-type m6g.2xlarge \
--enclave-options 'Enabled=true' \
--block-device-mappings "[{\"DeviceName\":\"/dev/xvda\",\"Ebs\":{\"VolumeSize\":20,\"DeleteOnTermination\":true}}]" \
--key-name $KEY_NAME \
--profile $AWS_PROFILE
```

These are the image types, ARM vs x86:

```
ami-05c3dc660cb6907f0 (64-bit (x86), uefi-preferred) - m6a.xlarge
ami-067df2907035c28c2 (64-bit (Arm), uefi) - m6g.xlarge
```

Log into the AWS console and get the IP address of the EC2 instance.

Add a new security group rule for allowing SSH access from IPv4 and IPv6. Also allow 80 and 443 while you are here.

## Basic server configurations after creation: 

Get the current IP address and ssh in:

```
ssh ec2-user@ec2-[your-ip].us-east-2.compute.amazonaws.com -i ~/.ssh/your_ssh_key.pem
```

Upgrade if needed:

```
/usr/bin/dnf check-release-update
```

## Install packages


Much of this comes from the nitro workshop: https://catalog.workshops.aws/nitro-enclaves/en-US/0-getting-started

Install nitro CLI things: 

```
sudo dnf install aws-nitro-enclaves-cli -y
```

```
sudo dnf install socat -y
```

```
sudo dnf install aws-nitro-enclaves-cli-devel -y
```

```
sudo usermod -aG ne ec2-user
```

```
sudo usermod -aG docker ec2-user
```

```
sudo systemctl enable --now docker
```

Verify:

```
nitro-cli --version
```

Configure nitro enclaves:

```
sudo vim /etc/nitro_enclaves/allocator.yaml
```

Basic recommendation:
```
# How much memory to allocate for enclaves (in MiB).
memory_mib: 21504
#
# How many CPUs to reserve for enclaves.
cpu_count: 6
```

Enable them:

```
sudo systemctl enable --now nitro-enclaves-allocator.service
```

If you need to reconfig and then restart:

```
sudo systemctl restart nitro-enclaves-allocator.service
```

## App deployment

When deploying the app in the Nitro enclave, make sure to set the `APP_MODE` to one of:
- `dev` for development environment
- `preview` for preview/staging environment
- `prod` for production environment
- `custom` for custom environment (requires `ENV_NAME` to be set)

For custom environments, you must also set the `ENV_NAME` environment variable. This name will be used to:
- Form the KMS key alias (`alias/open-secret-{env_name}-enclave`)

For example, to deploy a custom environment named "staging":
```sh
docker build -t opensecret \
--build-arg APP_MODE=custom \
--build-arg ENV_NAME=staging \
.
```

### Building and Deploying with Nix (Recommended)

The recommended way to build and deploy the enclave is using Nix, which provides reproducible builds:

1. First, build the required Nitro binaries (only needed once):
```bash
just build-nitro-bins
```

2. Build the EIF for your target environment:
```bash
# For development
nix build .#eif-dev

# For production
nix build .#eif-prod

# For preview
nix build .#eif-preview

# For custom environments
ENV_NAME=your_env_name nix build .#eif
```

This will create a symlink `result` pointing to the built EIF file.

3. Copy the EIF to your AWS parent instance:
```bash
# For development
just scp-eif-to-aws-dev

# For production
just scp-eif-to-aws-prod

# For preview
just scp-eif-to-aws-preview
```

4. Deploy the EIF:
```bash
# For development
just deploy-dev-nix

# For production
just deploy-prod-nix

# For preview
just deploy-preview-nix
```

The deployment process will:
1. Build the EIF
2. Copy it to the AWS parent instance
3. Prompt you to review the PCR values
4. After confirmation, terminate any existing enclave
5. Run the new enclave
6. Restart the socat proxy

### PCR Value Management

The Nix build process generates PCR (Platform Configuration Register) values that are used by AWS KMS for attestation. You can:

1. Copy PCR values to a reference file:
```bash
just copy-pcr-dev    # For development
just copy-pcr-prod   # For production
just copy-pcr-preview # For preview
```

2. Verify PCR values match the reference:
```bash
just verify-pcr-dev    # For development
just verify-pcr-prod   # For production
just verify-pcr-preview # For preview
```

This ensures the build is reproducible and matches the expected configuration.

## Setup SSL

Install nginx:

```
sudo dnf install nginx -y
```

Install acm:

```
sudo dnf install aws-nitro-enclaves-acm -y
```


Follow instructions for configuring [nginx](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-refapp.html) in the enclave.

After following the instructions, reboot the machine. And then start up this enclave program again.


## Socat proxy for SSL
Create a socat proxy service so that HTTP program on port 8080 can talk to the enclave:

```
sudo vim /etc/systemd/system/socat-proxy.service
```

Put in this info:

```
[Unit]
Description=Socat Proxy for Nitro Enclave
After=network.target

[Service]
Type=simple
User=ec2-user
ExecStart=/bin/bash -c 'ENCLAVES=$(nitro-cli describe-enclaves); echo "Enclaves: $ENCLAVES"; ENCLAVE_CID=$(echo "$ENCLAVES" | jq -r '\''.[] | select(.EnclaveName == "opensecret") | .EnclaveCID'\''); echo "ENCLAVE_CID: $ENCLAVE_CID"; if [ -n "$ENCLAVE_CID" ]; then socat TCP-LISTEN:8080,reuseaddr,fork VSOCK-CONNECT:$ENCLAVE_CID:5000; else echo "Enclave not found" >&2; exit 1; fi'
Restart=always

[Install]
WantedBy=multi-user.target
```

Activate service:
```
sudo systemctl daemon-reload
sudo systemctl enable socat-proxy.service
sudo systemctl start socat-proxy.service
sudo systemctl status socat-proxy.service
```

Restart socat proxy anytime there is a change to the enclave program:
```
sudo systemctl restart socat-proxy.service
```


## KMS Key

You need to create an AWS KMS key that the enclave can encrypt/decrypt things to. Name it according to your environment:
- `open-secret-dev-enclave` for dev environment
- `open-secret-preview1-enclave` for preview environment
- `open-secret-prod-enclave` for prod environment
- `open-secret-{env_name}-enclave` for custom environments (replace `{env_name}` with your ENV_NAME)

Here is an example policy, replace with your values:

```json
{
    "Version": "2012-10-17",
    "Id": "key-consolepolicy-3",
    "Statement": [
        {
            "Sid": "Limited Root Account Permissions",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn::{ACCOUNT}:root"
            },
            "Action": [
                "kms:Create*",
                "kms:Describe*",
                "kms:Enable*",
                "kms:List*",
                "kms:Put*",
                "kms:Update*",
                "kms:Revoke*",
                "kms:Disable*",
                "kms:Get*",
                "kms:Delete*",
                "kms:TagResource",
                "kms:UntagResource",
                "kms:ScheduleKeyDeletion",
                "kms:CancelKeyDeletion"
            ],
            "Resource": "*"
        },
        {
            "Sid": "Enable decrypt from enclave",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:sts::{ACCOUNT}:assumed-role/acm-role/i-{INSTNANCE}"
            },
            "Action": [
                "kms:Decrypt",
                "kms:GenerateDataKey*"
            ],
            "Resource": "*",
            "Condition": {
                "StringEqualsIgnoreCase": {
                    "kms:RecipientAttestation:ImageSha384": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                }
            }
        }
        {
            "Sid": "Enable encrypt from instance",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:sts::{{ACCOUNT}}:assumed-role/acm-role/i-{INSTANCE}"
            },
            "Action": "kms:Encrypt",
            "Resource": "*"
        }
    ]
}
```

Add a policy to your EC2's IAM role with this info: 

```
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Action": [
				"kms:Decrypt",
				"kms:GenerateDataKey",
				"kms:GenerateDataKeyWithoutPlaintext",
				"kms:CreateAlias",
				"kms:CreateKey",
				"kms:DeleteAlias",
				"kms:Describe*",
				"kms:GenerateRandom",
				"kms:Get*",
				"kms:List*",
				"kms:TagResource",
				"kms:UntagResource"
			],
			"Resource": "*"
		}
	]
}
```


## Credential Requester

This setup will run the credential requester on port 8003 of the parent instance, making it available for the enclave to request aws credentials.

The ec2 role will need a new inline policy to request secrets from Secrets Manager. Add the appropriate ARNs for your environment:

```json
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Action": "secretsmanager:GetSecretValue",
			"Resource": [
				"arn:aws:secretsmanager:us-east-2:XXX:secret:continuum_proxy_dev_api_key-XXX",
				"arn:aws:secretsmanager:us-east-2:XXX:secret:opensecret_dev_database_url-XXX",
				"arn:aws:secretsmanager:us-east-2:XXX:secret:continuum_proxy_preview1_api_key-XXX",
				"arn:aws:secretsmanager:us-east-2:XXX:secret:opensecret_preview1_database_url-XXX",
				"arn:aws:secretsmanager:us-east-2:XXX:secret:continuum_proxy_prod_api_key-XXX",
				"arn:aws:secretsmanager:us-east-2:XXX:secret:opensecret_prod_database_url-XXX",
				"arn:aws:secretsmanager:us-east-2:XXX:secret:tinfoil_proxy_dev_api_key-XXX",
				"arn:aws:secretsmanager:us-east-2:XXX:secret:tinfoil_proxy_preview1_api_key-XXX",
				"arn:aws:secretsmanager:us-east-2:XXX:secret:tinfoil_proxy_prod_api_key-XXX"
			]
		}
	]
}
```

Replace with the correct ARNs for those keys.

Build the docker image.

```sh
cd nitro-toolkit/credential_requester
docker build -t credential-requester .
```

Store it for transfer to the parent:

```sh
rm credential-requester.tar && docker save -o credential-requester.tar credential-requester
```

Now SCP into the AWS Parent instance:

```sh
scp credential-requester.tar ec2-user@[aws-parent-instance-ip]:~/
```

Load the docker image and tag it:

```sh
ssh ec2-user@[aws-parent-instance-ip]
docker load -i credential-requester.tar
docker tag localhost/credential-requester:latest credential-requester:latest
```

Now run it:

```sh
docker run -d --restart always --name credential-requester --device=/dev/vsock:/dev/vsock -v /var/run/vsock:/var/run/vsock --privileged -e PORT=8003 credential-requester:latest
```

## Logging Setup

To set up logging from the enclave to CloudWatch:

1. Build the logging Docker image:

```sh
cd nitro-toolkit/logging
docker build -t enclave-logging .
```

2. Save the Docker image:

```sh
docker save -o enclave-logging.tar enclave-logging
```

3. SCP the Docker image to the AWS parent instance:

```sh
scp enclave-logging.tar ec2-user@[aws-parent-instance-ip]:~/
```

4. SSH into the AWS parent instance and load the Docker image:

```sh
ssh ec2-user@[aws-parent-instance-ip]
docker load -i enclave-logging.tar
docker tag localhost/enclave-logging:latest enclave-logging:latest
```

5. Run the logging container:

```sh
docker run -d --restart always --name enclave-logging \
  --device=/dev/vsock:/dev/vsock \
  -v /var/run/vsock:/var/run/vsock \
  --privileged \
  -e VSOCK_PORT=8011 \
  -e LOG_GROUP=/aws/nitro-enclaves/enclave-dev \
  -e LOG_STREAM=enclave-logs-dev \
  -e AWS_REGION=us-east-2 \
  enclave-logging:latest
```

Replace `enclave-dev` and `enclave-logs-dev` with appropriate names for your development environment. For preview, use `enclave-preview` and `enclave-logs-preview`. For production, use `enclave-prod` and `enclave-logs-prod`.

### Setting up CloudWatch in AWS Console

Before running the logging container, you need to set up the necessary permissions and log groups in AWS CloudWatch. Follow these steps:

1. Log in to the AWS Management Console.

2. Navigate to the IAM (Identity and Access Management) service.

3. In the left sidebar, click on "Roles".

4. Find and click on the IAM role associated with your EC2 instance running the Nitro Enclave.

5. Click the "Add permissions" button and choose "Attach policies".

6. Search for and attach the "CloudWatchLogsFullAccess" policy. Note: In a production environment, you should create a more restrictive custom policy.

7. Navigate to the CloudWatch service in the AWS Console.

8. In the left sidebar, under "Logs", click on "Log groups".

9. Click the "Create log group" button.

10. Enter the name of your log group (e.g., `/aws/nitro-enclaves/enclave-dev` for development or `/aws/nitro-enclaves/enclave-prod` for production).

11. Click "Create" to finalize the log group creation.

After completing these steps, your EC2 instance will have the necessary permissions to write logs to CloudWatch, and the log group will be ready to receive logs from your Nitro Enclave.

Remember to repeat steps 9-11 if you need separate log groups for different environments (e.g., development and production).

Once CloudWatch is set up and the logging container is running, you can view your enclave logs by:

1. Going to the CloudWatch service in the AWS Console.
2. Clicking on "Log groups" in the left sidebar.
3. Selecting your log group (e.g., `/aws/nitro-enclaves/enclave-dev`).
4. Clicking on the log stream (e.g., `enclave-logs-dev`) to view the logs.

This setup allows you to monitor your Nitro Enclave's logs in real-time through the AWS CloudWatch console.

## Disk Space Management

Monitor disk space regularly to prevent service disruptions. A full disk can cause various issues including failed HTTP requests.

### Check disk usage:
```bash
df -h
du -sh /* 2>/dev/null | sort -rh | head -20
```

### Configure Docker log rotation:
Docker container logs can grow very large. Configure log rotation to prevent disk space issues:

```bash
echo '{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "3"
  }
}' | sudo tee /etc/docker/daemon.json

sudo systemctl restart docker
```

### Emergency cleanup commands:
If disk is full, use these commands to free up space:

```bash
# Clear large Docker logs
sudo find /var/lib/docker/containers -name "*-json.log" -size +100M -exec truncate -s 0 {} \;

# Clear systemd journal logs
sudo journalctl --vacuum-size=100M

# Clear old logs
sudo find /var/log -type f -name "*.log" -exec truncate -s 0 {} \;

# Docker cleanup
docker system prune -a -f
docker volume prune -f

# Clear tmp directories
sudo rm -rf /tmp/*
sudo rm -rf /var/tmp/*
```

### Regular maintenance:
Set up a cron job for regular cleanup:

```bash
sudo crontab -e
# Add this line for weekly cleanup:
0 2 * * 0 journalctl --vacuum-size=100M && docker system prune -f
```
