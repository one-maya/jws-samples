# Key Generation Scripts

This directory contains Python scripts for generating cryptographic keys for use with the JWS sample projects.

## Scripts Overview

- **`generate_hmac_key.py`** - Generate HMAC keys for symmetric signing (HS256, HS384, HS512)
- **`generate_asymmetric_keys.py`** - Generate RSA and ECDSA key pairs for asymmetric signing (RS256/384/512, ES256/384/512)
- **`generate_jwks.py`** - Generate JWKS (JSON Web Key Set) files from existing keys
- **`key_utils.py`** - Utility functions for key conversion, validation, and inspection

## Installation

Install the required dependencies:

```bash
cd scripts
pip install -r requirements.txt
```

## Usage

### Generate HMAC Keys

Generate a single HMAC key:
```bash
python generate_hmac_key.py --algorithm HS256 --output-dir keys
```

Generate keys for all HMAC algorithms:
```bash
python generate_hmac_key.py --all --output-dir keys
```

### Generate Asymmetric Key Pairs

Generate a single RSA key pair:
```bash
python generate_asymmetric_keys.py --algorithm RS256 --rsa-key-size 2048 --output-dir keys
```

Generate all RSA key pairs:
```bash
python generate_asymmetric_keys.py --all-rsa --output-dir keys
```

Generate all ECDSA key pairs:
```bash
python generate_asymmetric_keys.py --all-ecdsa --output-dir keys
```

Generate all asymmetric key pairs:
```bash
python generate_asymmetric_keys.py --all --output-dir keys
```

Generate asymmetric keys with combined JWKS:
```bash
python generate_asymmetric_keys.py --all --generate-combined-jwks --output-dir keys
```

### Generate JWKS Files

Create JWKS from a single key file:
```bash
python generate_jwks.py --key-file keys/rs256/rs256_private.pem --output jwks.json
```

Create JWKS from multiple key files in a directory:
```bash
python generate_jwks.py --key-dir keys --output combined_jwks.json
```

Auto-scan directory for keys and create JWKS:
```bash
python generate_jwks.py --scan-keys keys --output auto_jwks.json --public-only
```

Create public-only JWKS (recommended for distribution):
```bash
python generate_jwks.py --key-dir keys --output public_jwks.json --public-only --pretty
```

### Key Utilities

Get information about a key:
```bash
python key_utils.py info keys/rs256/rs256_private.pem
```

Convert key format:
```bash
python key_utils.py convert keys/rs256/rs256_private.pem --format base64 --output converted_key.b64
```

Validate key for algorithm:
```bash
python key_utils.py validate keys/rs256/rs256_private.pem --algorithm RS256
```

Get information about a JWKS file:
```bash
python key_utils.py jwks-info keys/combined_jwks.json
```

Validate a JWKS file:
```bash
python key_utils.py jwks-validate keys/combined_jwks.json
```

Convert JWKS to public-only:
```bash
python key_utils.py jwks-public keys/combined_jwks.json --output public_jwks.json
```

## Generated File Formats

Each key generation script creates multiple formats for different programming languages:

### HMAC Keys
- `{algorithm}_key.json` - Universal JSON format with all encodings
- `{algorithm}_key.base64` - Base64 encoded key
- `{algorithm}_key.hex` - Hexadecimal encoded key
- `{algorithm}_key.java` - Java format with usage example
- `{algorithm}_key.py` - Python format with usage example
- `{algorithm}_key.go` - Go format with usage example
- `{algorithm}_key.ts` - TypeScript format with usage example

### Asymmetric Key Pairs
- `{algorithm}_keypair.json` - Universal JSON format
- `{algorithm}_private.pem` - Private key in PEM format
- `{algorithm}_public.pem` - Public key in PEM format
- `{algorithm}_private.der` - Private key in DER format
- `{algorithm}_public.der` - Public key in DER format
- `{algorithm}_keys.java` - Java format with usage example
- `{algorithm}_keys.py` - Python format with usage example
- `{algorithm}_keys.go` - Go format with usage example
- `{algorithm}_keys.ts` - TypeScript format with usage example
- `{algorithm}_jwk.json` - Individual JWK (JSON Web Key) format
- `{algorithm}_public_jwk.json` - Public-only JWK format
- `{algorithm}_jwks.json` - Single-key JWKS format
- `{algorithm}_public_jwks.json` - Public-only single-key JWKS format

### JWKS Files
- `combined_jwks.json` - Combined JWKS with all generated keys (private)
- `combined_public_jwks.json` - Combined public-only JWKS (recommended for sharing)
- `jwks.json` - Generated JWKS from `generate_jwks.py` script

## JWKS (JSON Web Key Set) Support

JWKS is a standard format for distributing public keys for JWT verification. This toolset provides comprehensive JWKS support:

### What is JWKS?

JWKS (JSON Web Key Set) is a JSON format that represents a set of cryptographic keys. It's commonly used in:
- **OpenID Connect** - For distributing public keys at `/.well-known/jwks.json`
- **JWT verification** - Allowing clients to verify JWT signatures
- **Key rotation** - Managing multiple active keys with unique identifiers

### JWKS Features

- **Automatic generation** from existing key files
- **Public/private variants** - Generate public-only JWKS for distribution
- **Multiple key support** - Combine multiple algorithms in one JWKS
- **Key identification** - Automatic `kid` (Key ID) generation
- **Validation** - Comprehensive JWKS structure and content validation
- **Format conversion** - Convert between private and public JWKS

### Common JWKS Use Cases

1. **OpenID Connect Provider** - Serve public JWKS at `/.well-known/jwks.json`
2. **JWT verification** - Clients fetch JWKS to verify JWT signatures
3. **Key rotation** - Multiple keys with different IDs for smooth rotation
4. **Microservices** - Shared key distribution across services

### Example JWKS Structure

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "rs256-abc123",
      "alg": "RS256",
      "use": "sig",
      "n": "base64-encoded-modulus",
      "e": "AQAB"
    },
    {
      "kty": "EC",
      "kid": "es256-def456", 
      "alg": "ES256",
      "use": "sig",
      "crv": "P-256",
      "x": "base64-encoded-x",
      "y": "base64-encoded-y"
    }
  ]
}
```

## Security Best Practices

⚠️ **Important Security Notes:**

1. **Never commit keys to version control**
2. **Store private keys securely** - Use appropriate file permissions (600)
3. **Use environment variables** in production applications
4. **Implement key rotation** - Regularly update keys
5. **Use appropriate key sizes**:
   - HMAC: Minimum 256 bits
   - RSA: Minimum 2048 bits (3072+ recommended)
   - ECDSA: Use recommended curves (P-256, P-384, P-521)

## Algorithm Recommendations

### For Development/Testing
- **HMAC**: HS256 (simplest, fastest)
- **RSA**: RS256 with 2048-bit keys
- **ECDSA**: ES256 with P-256 curve

### For Production
- **HMAC**: HS256 or HS384
- **RSA**: RS256 with 3072+ bit keys
- **ECDSA**: ES256 or ES384

## Integration with Sample Projects

The generated keys can be directly used in the sample projects:

1. **Copy the appropriate format** for your target language
2. **Replace the hardcoded keys** in the sample code
3. **Load keys from environment variables** or secure configuration

### Example Integration

For the Java sample:
```bash
# Generate RS256 key pair
python generate_asymmetric_keys.py --algorithm RS256

# Copy the Java format to your project
cp keys/rs256/rs256_keys.java ../java-jws/src/main/resources/
```

For the Python sample:
```bash
# Generate HS256 key
python generate_hmac_key.py --algorithm HS256

# The key can be loaded in Python like this:
# import json
# with open('keys/hs256/hs256_key.json') as f:
#     key_data = json.load(f)
#     secret_key = base64.b64decode(key_data['base64'])
```

## Troubleshooting

### Common Issues

1. **Permission Denied**: Make sure scripts are executable
   ```bash
   chmod +x *.py
   ```

2. **Missing Dependencies**: Install required packages
   ```bash
   pip install -r requirements.txt
   ```

3. **Key Format Issues**: Use `key_utils.py` to inspect and convert keys
   ```bash
   python key_utils.py info your_key_file.pem
   ```

### Getting Help

Run any script with `--help` to see all available options:
```bash
python generate_hmac_key.py --help
python generate_asymmetric_keys.py --help
python key_utils.py --help
```