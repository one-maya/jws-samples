#!/usr/bin/env python3
"""
HMAC Key Generator

Generates secure HMAC keys for JWS signing with HS256, HS384, and HS512 algorithms.
Keys are generated using cryptographically secure random number generation.
"""

import secrets
import base64
import argparse
import json
from pathlib import Path

def generate_hmac_key(key_size: int = 256) -> bytes:
    """
    Generate a cryptographically secure HMAC key.
    
    Args:
        key_size (int): Key size in bits (256, 384, or 512)
        
    Returns:
        bytes: The generated key
    """
    if key_size not in [256, 384, 512]:
        raise ValueError("Key size must be 256, 384, or 512 bits")
    
    key_bytes = key_size // 8
    return secrets.token_bytes(key_bytes)

def save_key_formats(key: bytes, algorithm: str, output_dir: Path):
    """
    Save the key in multiple formats for different programming languages.
    
    Args:
        key (bytes): The generated key
        algorithm (str): The algorithm (HS256, HS384, HS512)
        output_dir (Path): Directory to save the keys
    """
    output_dir.mkdir(exist_ok=True)
    
    # Base64 encoded (for most applications)
    base64_key = base64.b64encode(key).decode('utf-8')
    
    # Hex encoded
    hex_key = key.hex()
    
    # Raw string (for languages that need it)
    raw_string = key.decode('latin-1')
    
    # Save in different formats
    formats = {
        'base64': base64_key,
        'hex': hex_key,
        'raw_bytes': list(key),
        'length_bits': len(key) * 8,
        'algorithm': algorithm
    }
    
    # JSON format (universal)
    with open(output_dir / f"{algorithm.lower()}_key.json", 'w') as f:
        json.dump(formats, f, indent=2)
    
    # Plain text formats for easy copying
    with open(output_dir / f"{algorithm.lower()}_key.base64", 'w') as f:
        f.write(base64_key)
    
    with open(output_dir / f"{algorithm.lower()}_key.hex", 'w') as f:
        f.write(hex_key)
    
    # Language-specific formats
    
    # Java format (Base64 string)
    with open(output_dir / f"{algorithm.lower()}_key.java", 'w') as f:
        f.write(f'// HMAC key for {algorithm}\n')
        f.write(f'private static final String SECRET_KEY = "{base64_key}";\n')
        f.write(f'// Usage: Base64.getDecoder().decode(SECRET_KEY)\n')
    
    # Python format
    with open(output_dir / f"{algorithm.lower()}_key.py", 'w') as f:
        f.write(f'# HMAC key for {algorithm}\n')
        f.write(f'SECRET_KEY = "{base64_key}"\n')
        f.write(f'# Usage: base64.b64decode(SECRET_KEY)\n')
    
    # Go format
    with open(output_dir / f"{algorithm.lower()}_key.go", 'w') as f:
        f.write(f'// HMAC key for {algorithm}\n')
        f.write(f'var secretKey = []byte("{raw_string}")\n')
        f.write(f'// Or use base64: "{base64_key}"\n')
    
    # TypeScript/JavaScript format
    with open(output_dir / f"{algorithm.lower()}_key.ts", 'w') as f:
        f.write(f'// HMAC key for {algorithm}\n')
        f.write(f'export const SECRET_KEY = "{base64_key}";\n')
        f.write(f'// Usage: Buffer.from(SECRET_KEY, "base64") or new TextEncoder().encode(SECRET_KEY)\n')

def main():
    parser = argparse.ArgumentParser(description='Generate HMAC keys for JWS signing')
    parser.add_argument('--algorithm', '-a', 
                       choices=['HS256', 'HS384', 'HS512'], 
                       default='HS256',
                       help='HMAC algorithm (default: HS256)')
    parser.add_argument('--output-dir', '-o', 
                       type=Path, 
                       default=Path('keys'),
                       help='Output directory for keys (default: keys)')
    parser.add_argument('--all', 
                       action='store_true',
                       help='Generate keys for all HMAC algorithms')
    
    args = parser.parse_args()
    
    algorithms = ['HS256', 'HS384', 'HS512'] if args.all else [args.algorithm]
    key_sizes = {'HS256': 256, 'HS384': 384, 'HS512': 512}
    
    print("🔐 Generating HMAC keys for JWS signing...")
    print()
    
    for algorithm in algorithms:
        print(f"Generating {algorithm} key...")
        
        key_size = key_sizes[algorithm]
        key = generate_hmac_key(key_size)
        
        # Create algorithm-specific directory
        algo_dir = args.output_dir / algorithm.lower()
        save_key_formats(key, algorithm, algo_dir)
        
        print(f"✅ {algorithm} key generated and saved to {algo_dir}/")
        print(f"   Key size: {key_size} bits ({len(key)} bytes)")
        print(f"   Base64: {base64.b64encode(key).decode()[:32]}...")
        print()
    
    print("🎉 Key generation complete!")
    print()
    print("📁 Generated files:")
    for algorithm in algorithms:
        algo_dir = args.output_dir / algorithm.lower()
        print(f"   {algo_dir}/")
        for file in sorted(algo_dir.glob("*")):
            print(f"     - {file.name}")
    
    print()
    print("⚠️  Security Notes:")
    print("   - Store these keys securely")
    print("   - Never commit keys to version control")
    print("   - Use environment variables in production")
    print("   - Implement proper key rotation")

if __name__ == "__main__":
    main()