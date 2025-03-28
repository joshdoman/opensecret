#!/usr/bin/env python3

import sys
import json
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_der_private_key

def generate_keypair():
    """
    Generates a P-384 (secp384r1) ECDSA keypair.
    Returns a tuple of (private_key, public_key).
    """
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return (private_key, public_key)

def export_keys_der_base64(private_key, public_key):
    """
    Exports keys in DER format, base64-encoded.
    Returns a tuple of (private_key_base64, public_key_base64).
    """
    # Export private key in PKCS#8 DER format
    private_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Export public key in SubjectPublicKeyInfo DER format
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Base64 encode
    private_b64 = base64.b64encode(private_der).decode('ascii')
    public_b64 = base64.b64encode(public_der).decode('ascii')
    
    return (private_b64, public_b64)

def sign_data_p1363(private_key, data_bytes):
    """
    Signs `data_bytes` using ECDSA+SHA384, returning a 'raw' P1363 signature (base64).
    Steps:
      1. We do a normal ECDSA sign (which yields DER).
      2. We parse (r, s) from DER.
      3. We concatenate r|s in fixed 48-byte big-endian form.
      4. We base64-encode that raw signature for output.
    """
    # 1. DER-encoded signature
    der_sig = private_key.sign(
        data_bytes,
        ec.ECDSA(hashes.SHA384())
    )

    # 2. Decode DER to (r, s)
    (r_int, s_int) = utils.decode_dss_signature(der_sig)

    # For P-384: each of r, s must be 48 bytes (384 bits). We'll big-endian encode & pad to 48.
    r_bytes = r_int.to_bytes(48, byteorder='big')
    s_bytes = s_int.to_bytes(48, byteorder='big')

    # 3. Concatenate to form raw signature
    raw_sig = r_bytes + s_bytes

    # 4. Base64-encode
    return base64.b64encode(raw_sig).decode('ascii')


def main():
    # Example usage from the command line:
    #   ./pcr_sign.py generate-keys
    #   ./pcr_sign.py sign <base64-privkey> '{"PCR0":"...","timestamp":1234}'
    if len(sys.argv) < 2:
        print("Usage:")
        print("  pcr_sign.py generate-keys")
        print("  pcr_sign.py sign <base64-private-key> <json-string>")
        sys.exit(1)

    command = sys.argv[1]

    if command == "generate-keys":
        # Generate a new P-384 key pair, output them in base64 DER
        priv, pub = generate_keypair()
        priv_b64, pub_b64 = export_keys_der_base64(priv, pub)
        
        # Optionally also print them in PEM for human readability:
        private_pem = (
            "-----BEGIN PRIVATE KEY-----\n"
            + "\n".join(priv_b64[i:i+64] for i in range(0, len(priv_b64), 64))
            + "\n-----END PRIVATE KEY-----\n"
        )
        public_pem = (
            "-----BEGIN PUBLIC KEY-----\n"
            + "\n".join(pub_b64[i:i+64] for i in range(0, len(pub_b64), 64))
            + "\n-----END PUBLIC KEY-----\n"
        )
        
        # Display everything in a clear format
        print("===== KEYS FOR PCR SIGNING SYSTEM =====\n")
        
        print("===== FOR ENVIRONMENT VARIABLES =====")
        print(f"export SIGNING_PRIVATE_KEY='{priv_b64}'")
        print(f"export SIGNING_PUBLIC_KEY='{base64.b64encode(private_pem.encode()).decode()}'")
        print("")
        
        print("===== FOR FRONTEND INTEGRATION =====")
        print("// Base64-encoded DER public key for verifying PCR signatures (add to your frontend)")
        print(f"const PCR_VERIFICATION_PUBLIC_KEY_B64 = \"{pub_b64}\";")
        print("")
        
        print("===== ADDITIONAL KEY FORMATS =====")
        print("===== PRIVATE KEY (PKCS#8 DER BASE64) =====")
        print(priv_b64)
        print("\n===== PUBLIC KEY (SPKI DER BASE64) =====")
        print(pub_b64)
        print("\n===== PRIVATE KEY (PEM) =====\n" + private_pem)
        print("===== PUBLIC KEY (PEM) =====\n" + public_pem)
        
        print("\n===== VERIFICATION COMMAND =====")
        print("just verify-pcr-history dev")
        print("")

    elif command == "sign":
        if len(sys.argv) < 4:
            print("Usage: pcr_sign.py sign <base64-private-key> <json-string>")
            sys.exit(1)

        base64_priv = sys.argv[2]
        json_str = sys.argv[3]

        # Re-import the private key from base64 DER
        priv_der = base64.b64decode(base64_priv)
        private_key = serialization.load_der_private_key(priv_der, password=None)

        # Sign (raw p1363)
        sig_b64 = sign_data_p1363(private_key, json_str.encode('utf-8'))
        print("Signature (raw p1363, base64):", sig_b64)

    else:
        print("Unknown command:", command)
        sys.exit(1)


if __name__ == "__main__":
    main()