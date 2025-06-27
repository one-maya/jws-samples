#!/usr/bin/env python3
"""
JWKS Generator

Standalone script for generating JWKS (JSON Web Key Set) files from existing key files
or creating new keys specifically for JWKS usage.
"""

import argparse
import json
import uuid
from pathlib import Path
from typing import List, Dict, Any
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from jwcrypto import jwk

def load_key_from_file(file_path: Path):
    """
    Load a key from PEM, DER, or other formats.
    
    Args:
        file_path (Path): Path to the key file
        
    Returns:
        Key object (private or public key)
    """
    try:
        with open(file_path, 'rb') as f:
            key_data = f.read()
        
        # Try PEM format first
        try:
            if b'PRIVATE KEY' in key_data:
                return serialization.load_pem_private_key(key_data, password=None)
            elif b'PUBLIC KEY' in key_data:
                return serialization.load_pem_public_key(key_data)
        except Exception:
            pass
        
        # Try DER format
        try:
            return serialization.load_der_private_key(key_data, password=None)
        except Exception:
            try:
                return serialization.load_der_public_key(key_data)
            except Exception:
                pass
                
        raise ValueError(f"Unable to load key from {file_path}")
        
    except Exception as e:
        raise ValueError(f"Error loading key from {file_path}: {e}")

def create_jwk_from_key_file(file_path: Path, algorithm: str = None, key_id: str = None, use: str = "sig") -> Dict[str, Any]:
    """
    Create a JWK from a key file.
    
    Args:
        file_path (Path): Path to the key file
        algorithm (str): JWS algorithm (RS256, ES256, etc.)
        key_id (str): Key ID (will generate if not provided)
        use (str): Key use ('sig' for signature, 'enc' for encryption)
        
    Returns:
        Dict[str, Any]: JWK representation
    """
    key = load_key_from_file(file_path)
    
    if key_id is None:
        key_id = str(uuid.uuid4())
    
    # Determine algorithm if not specified
    if algorithm is None:
        if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
            algorithm = "RS256"  # Default RSA algorithm
        elif isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
            # Determine based on curve
            if isinstance(key, ec.EllipticCurvePrivateKey):
                curve_name = key.curve.name.lower()
            else:
                curve_name = key.curve.name.lower()
                
            curve_to_algo = {
                'secp256r1': 'ES256',
                'secp384r1': 'ES384', 
                'secp521r1': 'ES512'
            }
            algorithm = curve_to_algo.get(curve_name, 'ES256')
    
    # Convert to PEM for jwcrypto
    if isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        pem_data = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        pem_data = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    # Create JWK
    jwk_obj = jwk.JWK.from_pem(pem_data)
    jwk_dict = json.loads(jwk_obj.export())
    
    # Add metadata
    jwk_dict['kid'] = key_id
    jwk_dict['alg'] = algorithm
    jwk_dict['use'] = use
    
    return jwk_dict

def create_public_jwk_from_private(jwk_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a public JWK from a private JWK by removing private components.
    
    Args:
        jwk_dict (Dict[str, Any]): Private JWK
        
    Returns:
        Dict[str, Any]: Public JWK
    """
    # Remove private key components
    private_components = ['d', 'dp', 'dq', 'p', 'q', 'qi']
    return {k: v for k, v in jwk_dict.items() if k not in private_components}

def scan_directory_for_keys(directory: Path) -> List[Path]:
    """
    Scan a directory for key files.
    
    Args:
        directory (Path): Directory to scan
        
    Returns:
        List[Path]: List of key file paths
    """
    key_extensions = ['.pem', '.der', '.key']
    key_files = []
    
    for ext in key_extensions:
        key_files.extend(directory.glob(f'**/*{ext}'))
    
    # Filter for likely key files (exclude public keys if private key exists)
    private_keys = [f for f in key_files if 'private' in f.name.lower()]
    public_keys = [f for f in key_files if 'public' in f.name.lower()]
    
    # Prefer private keys, but include public keys if no corresponding private key
    result = private_keys[:]
    for pub_key in public_keys:
        # Check if there's a corresponding private key
        base_name = pub_key.name.replace('public', 'private').replace('_public', '_private')
        if not any(base_name in priv.name for priv in private_keys):
            result.append(pub_key)
    
    return result

def main():
    parser = argparse.ArgumentParser(description='Generate JWKS files from key files')
    
    # Input options
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--key-file', '-k', type=Path, help='Single key file to convert')
    group.add_argument('--key-dir', '-d', type=Path, help='Directory containing key files')
    group.add_argument('--scan-keys', '-s', type=Path, help='Scan directory for keys automatically')
    
    # Output options
    parser.add_argument('--output', '-o', type=Path, default=Path('jwks.json'),
                       help='Output JWKS file (default: jwks.json)')
    parser.add_argument('--public-only', action='store_true',
                       help='Generate public JWKS only (no private key material)')
    parser.add_argument('--algorithm', '-a', 
                       choices=['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'],
                       help='Force specific algorithm (auto-detect if not specified)')
    parser.add_argument('--key-id', help='Key ID for single key (auto-generate if not specified)')
    parser.add_argument('--use', choices=['sig', 'enc'], default='sig',
                       help='Key use (sig=signature, enc=encryption, default: sig)')
    
    # Additional options
    parser.add_argument('--pretty', action='store_true',
                       help='Pretty-print JSON output')
    parser.add_argument('--validate', action='store_true',
                       help='Validate generated JWKS')
    
    args = parser.parse_args()
    
    print("🔑 Generating JWKS from key files...")
    print()
    
    # Collect key files
    key_files = []
    if args.key_file:
        key_files = [args.key_file]
    elif args.key_dir:
        key_files = list(args.key_dir.glob('*'))
        key_files = [f for f in key_files if f.is_file()]
    elif args.scan_keys:
        key_files = scan_directory_for_keys(args.scan_keys)
    
    if not key_files:
        print("❌ No key files found")
        return
    
    # Generate JWKs
    jwks_keys = []
    
    for i, key_file in enumerate(key_files):
        try:
            print(f"Processing {key_file.name}...")
            
            # Generate key ID if not specified
            if args.key_id and len(key_files) == 1:
                kid = args.key_id
            else:
                kid = f"key-{i+1}-{str(uuid.uuid4())[:8]}"
            
            jwk_dict = create_jwk_from_key_file(
                key_file, 
                args.algorithm, 
                kid, 
                args.use
            )
            
            # Convert to public key if requested
            if args.public_only:
                jwk_dict = create_public_jwk_from_private(jwk_dict)
            
            jwks_keys.append(jwk_dict)
            
            print(f"✅ Added key: {kid} ({jwk_dict.get('kty', 'unknown')} {jwk_dict.get('alg', 'unknown')})")
            
        except Exception as e:
            print(f"❌ Failed to process {key_file.name}: {e}")
    
    if not jwks_keys:
        print("❌ No valid keys processed")
        return
    
    # Create JWKS
    jwks = {
        "keys": jwks_keys
    }
    
    # Validate if requested
    if args.validate:
        print()
        print("🔍 Validating JWKS...")
        try:
            # Basic validation
            assert isinstance(jwks, dict), "JWKS must be a dictionary"
            assert "keys" in jwks, "JWKS must have 'keys' field"
            assert isinstance(jwks["keys"], list), "JWKS 'keys' must be a list"
            
            for i, key in enumerate(jwks["keys"]):
                assert isinstance(key, dict), f"Key {i} must be a dictionary"
                assert "kty" in key, f"Key {i} must have 'kty' field"
                assert "kid" in key, f"Key {i} must have 'kid' field"
            
            print("✅ JWKS validation passed")
            
        except Exception as e:
            print(f"❌ JWKS validation failed: {e}")
            return
    
    # Save JWKS
    indent = 2 if args.pretty else None
    
    with open(args.output, 'w') as f:
        json.dump(jwks, f, indent=indent)
    
    print()
    print(f"🎉 JWKS generated successfully!")
    print(f"   File: {args.output}")
    print(f"   Keys: {len(jwks_keys)}")
    print(f"   Type: {'Public only' if args.public_only else 'Private + Public'}")
    
    # Show summary
    print()
    print("📋 JWKS Summary:")
    for key in jwks_keys:
        key_type = f"{key.get('kty', 'unknown')}"
        if key_type == 'RSA':
            key_size = len(key.get('n', '')) * 6 // 8  # Rough estimate from base64
            key_type += f" (~{key_size} bits)"
        elif key_type == 'EC':
            key_type += f" ({key.get('crv', 'unknown')})"
            
        print(f"   - {key.get('kid', 'no-id')}: {key_type} for {key.get('alg', 'unknown')}")
    
    print()
    print("💡 Usage Notes:")
    print("   - Public JWKS can be shared freely for signature verification")
    print("   - Private JWKS should be kept secure and used only for signing")
    print("   - The 'kid' (Key ID) is used to identify which key to use")
    print("   - Serve public JWKS at /.well-known/jwks.json for OIDC compliance")

if __name__ == "__main__":
    main()