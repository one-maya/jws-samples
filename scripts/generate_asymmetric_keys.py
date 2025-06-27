#!/usr/bin/env python3
"""
Asymmetric Key Pair Generator

Generates RSA and ECDSA key pairs for JWS signing with RS256, RS384, RS512,
ES256, ES384, and ES512 algorithms.
"""

import argparse
import json
import uuid
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
import base64
from jwcrypto import jwk

def generate_rsa_key_pair(key_size: int = 2048):
    """
    Generate an RSA key pair.
    
    Args:
        key_size (int): Key size in bits (2048, 3072, 4096)
        
    Returns:
        tuple: (private_key, public_key)
    """
    if key_size not in [2048, 3072, 4096]:
        raise ValueError("RSA key size must be 2048, 3072, or 4096 bits")
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    
    return private_key, public_key

def generate_ecdsa_key_pair(curve_name: str):
    """
    Generate an ECDSA key pair.
    
    Args:
        curve_name (str): Curve name (P-256, P-384, P-521)
        
    Returns:
        tuple: (private_key, public_key)
    """
    curves = {
        'P-256': ec.SECP256R1(),
        'P-384': ec.SECP384R1(),
        'P-521': ec.SECP521R1()
    }
    
    if curve_name not in curves:
        raise ValueError(f"Unsupported curve: {curve_name}")
    
    private_key = ec.generate_private_key(curves[curve_name])
    public_key = private_key.public_key()
    
    return private_key, public_key

def create_jwk_from_key(private_key, public_key, algorithm: str, key_id: str = None):
    """
    Create a JWK (JSON Web Key) from a key pair.
    
    Args:
        private_key: The private key object
        public_key: The public key object  
        algorithm (str): The algorithm (RS256, ES256, etc.)
        key_id (str): Optional key ID, will generate one if not provided
        
    Returns:
        dict: JWK representation
    """
    if key_id is None:
        key_id = str(uuid.uuid4())
    
    # Convert to PEM format for jwcrypto
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    
    # Create JWK from private key (includes public key)
    key = jwk.JWK.from_pem(private_pem)
    
    # Get the JWK as dict
    jwk_dict = json.loads(key.export())
    
    # Add metadata
    jwk_dict['kid'] = key_id
    jwk_dict['alg'] = algorithm
    jwk_dict['use'] = 'sig'
    
    return jwk_dict

def create_jwks_from_keys(keys_info: list):
    """
    Create a JWKS (JSON Web Key Set) from multiple keys.
    
    Args:
        keys_info (list): List of dicts containing key info
        
    Returns:
        dict: JWKS representation
    """
    jwks = {
        "keys": []
    }
    
    for key_info in keys_info:
        jwk_dict = create_jwk_from_key(
            key_info['private_key'],
            key_info['public_key'], 
            key_info['algorithm'],
            key_info.get('key_id')
        )
        jwks["keys"].append(jwk_dict)
    
    return jwks

def create_public_jwks_from_keys(keys_info: list):
    """
    Create a public JWKS (JSON Web Key Set) with only public keys.
    
    Args:
        keys_info (list): List of dicts containing key info
        
    Returns:
        dict: Public JWKS representation (no private key material)
    """
    jwks = {
        "keys": []
    }
    
    for key_info in keys_info:
        # Create JWK from private key first
        jwk_dict = create_jwk_from_key(
            key_info['private_key'],
            key_info['public_key'], 
            key_info['algorithm'],
            key_info.get('key_id')
        )
        
        # Remove private key components
        public_jwk = {k: v for k, v in jwk_dict.items() if k not in ['d', 'dp', 'dq', 'p', 'q', 'qi']}
        
        jwks["keys"].append(public_jwk)
    
    return jwks

def save_key_pair_formats(private_key, public_key, algorithm: str, output_dir: Path):
    """
    Save the key pair in multiple formats for different programming languages.
    
    Args:
        private_key: The private key object
        public_key: The public key object
        algorithm (str): The algorithm (RS256, ES256, etc.)
        output_dir (Path): Directory to save the keys
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    
    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    
    # Base64 encoded versions (without PEM headers)
    private_der = private_key.private_bytes(
        encoding=Encoding.DER,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    public_der = public_key.public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    
    private_b64 = base64.b64encode(private_der).decode()
    public_b64 = base64.b64encode(public_der).decode()
    
    # Create key information
    key_info = {
        'algorithm': algorithm,
        'key_type': 'RSA' if algorithm.startswith('RS') else 'ECDSA',
        'private_key_pem': private_pem.decode(),
        'public_key_pem': public_pem.decode(),
        'private_key_base64': private_b64,
        'public_key_base64': public_b64
    }
    
    # Save JSON format
    with open(output_dir / f"{algorithm.lower()}_keypair.json", 'w') as f:
        json.dump(key_info, f, indent=2)
    
    # Save PEM files
    with open(output_dir / f"{algorithm.lower()}_private.pem", 'wb') as f:
        f.write(private_pem)
    
    with open(output_dir / f"{algorithm.lower()}_public.pem", 'wb') as f:
        f.write(public_pem)
    
    # Save DER files
    with open(output_dir / f"{algorithm.lower()}_private.der", 'wb') as f:
        f.write(private_der)
    
    with open(output_dir / f"{algorithm.lower()}_public.der", 'wb') as f:
        f.write(public_der)
    
    # Language-specific formats
    
    # Java format
    with open(output_dir / f"{algorithm.lower()}_keys.java", 'w') as f:
        f.write(f'// {algorithm} Key Pair\n')
        f.write('// Private Key (PKCS8 format)\n')
        f.write(f'private static final String PRIVATE_KEY_PEM = \n    "{private_pem.decode().replace(chr(10), "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").strip()}";\n\n')
        f.write('// Public Key\n')
        f.write(f'private static final String PUBLIC_KEY_PEM = \n    "{public_pem.decode().replace(chr(10), "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").strip()}";\n\n')
        f.write('// Usage:\n')
        f.write('// KeyFactory keyFactory = KeyFactory.getInstance("' + ('RSA' if algorithm.startswith('RS') else 'EC') + '");\n')
        f.write('// PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(PRIVATE_KEY_PEM)));\n')
        f.write('// PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(PUBLIC_KEY_PEM)));\n')
    
    # Python format
    with open(output_dir / f"{algorithm.lower()}_keys.py", 'w') as f:
        f.write(f'# {algorithm} Key Pair\n')
        f.write('PRIVATE_KEY_PEM = """' + private_pem.decode() + '"""\n\n')
        f.write('PUBLIC_KEY_PEM = """' + public_pem.decode() + '"""\n\n')
        f.write('# Usage:\n')
        f.write('# from cryptography.hazmat.primitives import serialization\n')
        f.write('# private_key = serialization.load_pem_private_key(PRIVATE_KEY_PEM.encode(), password=None)\n')
        f.write('# public_key = serialization.load_pem_public_key(PUBLIC_KEY_PEM.encode())\n')
    
    # Go format
    with open(output_dir / f"{algorithm.lower()}_keys.go", 'w') as f:
        f.write(f'// {algorithm} Key Pair\n')
        f.write('const PrivateKeyPEM = `' + private_pem.decode() + '`\n\n')
        f.write('const PublicKeyPEM = `' + public_pem.decode() + '`\n\n')
        f.write('// Usage:\n')
        f.write('// import "crypto/x509"\n')
        f.write('// privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)\n')
        f.write('// publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)\n')
    
    # TypeScript format
    with open(output_dir / f"{algorithm.lower()}_keys.ts", 'w') as f:
        f.write(f'// {algorithm} Key Pair\n')
        f.write('export const PRIVATE_KEY_PEM = `' + private_pem.decode() + '`;\n\n')
        f.write('export const PUBLIC_KEY_PEM = `' + public_pem.decode() + '`;\n\n')
        f.write('// Usage with jose library:\n')
        f.write('// import { importPKCS8, importSPKI } from "jose";\n')
        f.write('// const privateKey = await importPKCS8(PRIVATE_KEY_PEM, "' + algorithm + '");\n')
        f.write('// const publicKey = await importSPKI(PUBLIC_KEY_PEM, "' + algorithm + '");\n')
    
    # Generate JWK and JWKS
    key_id = f"{algorithm.lower()}-{str(uuid.uuid4())[:8]}"
    
    # Create JWK (includes private key)
    jwk_dict = create_jwk_from_key(private_key, public_key, algorithm, key_id)
    
    # Save full JWK (with private key)
    with open(output_dir / f"{algorithm.lower()}_jwk.json", 'w') as f:
        json.dump(jwk_dict, f, indent=2)
    
    # Create public-only JWK
    public_jwk = {k: v for k, v in jwk_dict.items() if k not in ['d', 'dp', 'dq', 'p', 'q', 'qi']}
    
    # Save public JWK
    with open(output_dir / f"{algorithm.lower()}_public_jwk.json", 'w') as f:
        json.dump(public_jwk, f, indent=2)
    
    # Create single-key JWKS (private)
    jwks_private = {"keys": [jwk_dict]}
    with open(output_dir / f"{algorithm.lower()}_jwks.json", 'w') as f:
        json.dump(jwks_private, f, indent=2)
    
    # Create single-key JWKS (public only)  
    jwks_public = {"keys": [public_jwk]}
    with open(output_dir / f"{algorithm.lower()}_public_jwks.json", 'w') as f:
        json.dump(jwks_public, f, indent=2)

def main():
    parser = argparse.ArgumentParser(description='Generate asymmetric key pairs for JWS signing')
    parser.add_argument('--algorithm', '-a',
                       choices=['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'],
                       default='RS256',
                       help='Signature algorithm (default: RS256)')
    parser.add_argument('--rsa-key-size',
                       type=int,
                       choices=[2048, 3072, 4096],
                       default=2048,
                       help='RSA key size in bits (default: 2048)')
    parser.add_argument('--output-dir', '-o',
                       type=Path,
                       default=Path('keys'),
                       help='Output directory for keys (default: keys)')
    parser.add_argument('--all-rsa',
                       action='store_true',
                       help='Generate keys for all RSA algorithms (RS256, RS384, RS512)')
    parser.add_argument('--all-ecdsa',
                       action='store_true',
                       help='Generate keys for all ECDSA algorithms (ES256, ES384, ES512)')
    parser.add_argument('--all',
                       action='store_true',
                       help='Generate keys for all algorithms')
    parser.add_argument('--generate-combined-jwks',
                       action='store_true',
                       help='Generate combined JWKS file with all keys')
    
    args = parser.parse_args()
    
    algorithms = []
    if args.all:
        algorithms = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512']
    elif args.all_rsa:
        algorithms = ['RS256', 'RS384', 'RS512']
    elif args.all_ecdsa:
        algorithms = ['ES256', 'ES384', 'ES512']
    else:
        algorithms = [args.algorithm]
    
    print("🔐 Generating asymmetric key pairs for JWS signing...")
    print()
    
    # Track generated keys for combined JWKS
    generated_keys = []
    
    for algorithm in algorithms:
        print(f"Generating {algorithm} key pair...")
        
        try:
            if algorithm.startswith('RS'):
                # RSA key pair
                private_key, public_key = generate_rsa_key_pair(args.rsa_key_size)
                key_info = f"RSA {args.rsa_key_size} bits"
            else:
                # ECDSA key pair
                curve_map = {'ES256': 'P-256', 'ES384': 'P-384', 'ES512': 'P-521'}
                curve = curve_map[algorithm]
                private_key, public_key = generate_ecdsa_key_pair(curve)
                key_info = f"ECDSA {curve}"
            
            # Create algorithm-specific directory
            algo_dir = args.output_dir / algorithm.lower()
            save_key_pair_formats(private_key, public_key, algorithm, algo_dir)
            
            # Store key info for combined JWKS
            if args.generate_combined_jwks:
                key_id = f"{algorithm.lower()}-{str(uuid.uuid4())[:8]}"
                generated_keys.append({
                    'private_key': private_key,
                    'public_key': public_key,
                    'algorithm': algorithm,
                    'key_id': key_id
                })
            
            print(f"✅ {algorithm} key pair generated and saved to {algo_dir}/")
            print(f"   Key type: {key_info}")
            print()
            
        except Exception as e:
            print(f"❌ Failed to generate {algorithm} key pair: {e}")
            print()
    
    # Generate combined JWKS if requested
    if args.generate_combined_jwks and generated_keys:
        print("🔗 Generating combined JWKS files...")
        
        # Create combined private JWKS (with private key material)
        combined_jwks_private = create_jwks_from_keys(generated_keys)
        with open(args.output_dir / "combined_jwks.json", 'w') as f:
            json.dump(combined_jwks_private, f, indent=2)
        
        # Create combined public JWKS (public keys only)
        combined_jwks_public = create_public_jwks_from_keys(generated_keys)
        with open(args.output_dir / "combined_public_jwks.json", 'w') as f:
            json.dump(combined_jwks_public, f, indent=2)
        
        print(f"✅ Combined JWKS files generated:")
        print(f"   - {args.output_dir}/combined_jwks.json (private)")
        print(f"   - {args.output_dir}/combined_public_jwks.json (public)")
        print(f"   - Contains {len(generated_keys)} keys")
        print()
    
    print("🎉 Key pair generation complete!")
    print()
    print("📁 Generated files for each algorithm:")
    for algorithm in algorithms:
        algo_dir = args.output_dir / algorithm.lower()
        if algo_dir.exists():
            print(f"   {algo_dir}/")
            for file in sorted(algo_dir.glob("*")):
                print(f"     - {file.name}")
    
    print()
    print("⚠️  Security Notes:")
    print("   - Private keys should be kept secure and never shared")
    print("   - Public keys can be shared freely")
    print("   - Never commit private keys to version control")
    print("   - Use environment variables or secure key stores in production")
    print("   - Implement proper key rotation and lifecycle management")

if __name__ == "__main__":
    main()