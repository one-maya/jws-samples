#!/usr/bin/env python3
"""
Key Utilities

Utility functions for converting between different key formats,
validating keys, and extracting key information.
"""

import argparse
import base64
import json
import uuid
from pathlib import Path
from typing import Dict, Any, Optional, List
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import jwt
from jwcrypto import jwk

def load_key_from_file(file_path: Path) -> Any:
    """
    Load a key from various file formats.
    
    Args:
        file_path (Path): Path to the key file
        
    Returns:
        Any: The loaded key object
    """
    try:
        with open(file_path, 'rb') as f:
            key_data = f.read()
        
        # Try to load as PEM first
        try:
            if b'PRIVATE KEY' in key_data:
                return serialization.load_pem_private_key(key_data, password=None)
            elif b'PUBLIC KEY' in key_data:
                return serialization.load_pem_public_key(key_data)
        except Exception:
            pass
        
        # Try to load as DER
        try:
            return serialization.load_der_private_key(key_data, password=None)
        except Exception:
            try:
                return serialization.load_der_public_key(key_data)
            except Exception:
                pass
        
        # Try to load as base64 encoded
        try:
            decoded = base64.b64decode(key_data)
            try:
                return serialization.load_der_private_key(decoded, password=None)
            except Exception:
                return serialization.load_der_public_key(decoded)
        except Exception:
            pass
            
        raise ValueError(f"Unable to load key from {file_path}")
        
    except Exception as e:
        raise ValueError(f"Error loading key from {file_path}: {e}")

def get_key_info(key) -> Dict[str, Any]:
    """
    Extract information about a key.
    
    Args:
        key: The key object
        
    Returns:
        Dict[str, Any]: Key information
    """
    info = {}
    
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        info['type'] = 'RSA'
        if isinstance(key, rsa.RSAPrivateKey):
            info['key_class'] = 'Private'
            info['key_size'] = key.key_size
            info['public_exponent'] = key.public_numbers().e
        else:
            info['key_class'] = 'Public'
            info['key_size'] = key.key_size
            info['public_exponent'] = key.public_numbers().e
            
        # Suggest appropriate algorithms
        if info['key_size'] >= 2048:
            info['suggested_algorithms'] = ['RS256', 'RS384', 'RS512']
        else:
            info['suggested_algorithms'] = []
            info['warning'] = 'Key size too small for secure RSA signatures'
            
    elif isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        info['type'] = 'ECDSA'
        if isinstance(key, ec.EllipticCurvePrivateKey):
            info['key_class'] = 'Private'
            curve = key.curve
        else:
            info['key_class'] = 'Public'
            curve = key.curve
        
        info['curve'] = curve.name
        info['key_size'] = curve.key_size
        
        # Map curves to algorithms
        curve_to_algo = {
            'secp256r1': ['ES256'],
            'secp384r1': ['ES384'],
            'secp521r1': ['ES512']
        }
        info['suggested_algorithms'] = curve_to_algo.get(curve.name.lower(), [])
        
    else:
        info['type'] = 'Unknown'
        info['key_class'] = 'Unknown'
    
    return info

def convert_key_format(key, output_format: str) -> bytes:
    """
    Convert a key to the specified format.
    
    Args:
        key: The key object
        output_format (str): Target format (pem, der, base64)
        
    Returns:
        bytes: The converted key data
    """
    if isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        # Private key
        if output_format.lower() == 'pem':
            return key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        elif output_format.lower() == 'der':
            return key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        elif output_format.lower() == 'base64':
            der_data = key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            return base64.b64encode(der_data)
    
    elif isinstance(key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
        # Public key
        if output_format.lower() == 'pem':
            return key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        elif output_format.lower() == 'der':
            return key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        elif output_format.lower() == 'base64':
            der_data = key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return base64.b64encode(der_data)
    
    raise ValueError(f"Unsupported key type or format: {type(key)}, {output_format}")

def validate_key_for_algorithm(key, algorithm: str) -> Dict[str, Any]:
    """
    Validate if a key is suitable for the specified algorithm.
    
    Args:
        key: The key object
        algorithm (str): JWS algorithm
        
    Returns:
        Dict[str, Any]: Validation result
    """
    result = {
        'valid': False,
        'algorithm': algorithm,
        'messages': []
    }
    
    if algorithm in ['HS256', 'HS384', 'HS512']:
        result['messages'].append('HMAC algorithms require symmetric keys, not asymmetric key pairs')
        return result
    
    key_info = get_key_info(key)
    
    if algorithm in ['RS256', 'RS384', 'RS512']:
        if key_info['type'] != 'RSA':
            result['messages'].append(f'Algorithm {algorithm} requires RSA keys, got {key_info["type"]}')
            return result
        
        if key_info['key_size'] < 2048:
            result['messages'].append(f'RSA key size {key_info["key_size"]} is too small for secure signatures (minimum 2048)')
            return result
        
        result['valid'] = True
        result['messages'].append(f'RSA key is suitable for {algorithm}')
        
    elif algorithm in ['ES256', 'ES384', 'ES512']:
        if key_info['type'] != 'ECDSA':
            result['messages'].append(f'Algorithm {algorithm} requires ECDSA keys, got {key_info["type"]}')
            return result
        
        required_curves = {
            'ES256': 'secp256r1',
            'ES384': 'secp384r1',
            'ES512': 'secp521r1'
        }
        
        required_curve = required_curves[algorithm]
        actual_curve = key_info.get('curve', '').lower()
        
        if actual_curve != required_curve:
            result['messages'].append(f'Algorithm {algorithm} requires curve {required_curve}, got {actual_curve}')
            return result
        
        result['valid'] = True
        result['messages'].append(f'ECDSA key is suitable for {algorithm}')
    
    else:
        result['messages'].append(f'Unknown algorithm: {algorithm}')
    
    return result

def load_jwks_from_file(file_path: Path) -> Dict[str, Any]:
    """
    Load a JWKS from a JSON file.
    
    Args:
        file_path (Path): Path to the JWKS file
        
    Returns:
        Dict[str, Any]: JWKS data
    """
    try:
        with open(file_path, 'r') as f:
            jwks = json.load(f)
        
        if not isinstance(jwks, dict) or 'keys' not in jwks:
            raise ValueError("Invalid JWKS format")
        
        return jwks
    except Exception as e:
        raise ValueError(f"Error loading JWKS from {file_path}: {e}")

def validate_jwks(jwks: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate a JWKS structure and contents.
    
    Args:
        jwks (Dict[str, Any]): JWKS to validate
        
    Returns:
        Dict[str, Any]: Validation result
    """
    result = {
        'valid': False,
        'messages': [],
        'warnings': []
    }
    
    try:
        # Basic structure validation
        if not isinstance(jwks, dict):
            result['messages'].append("JWKS must be a JSON object")
            return result
        
        if 'keys' not in jwks:
            result['messages'].append("JWKS must contain 'keys' field")
            return result
        
        if not isinstance(jwks['keys'], list):
            result['messages'].append("JWKS 'keys' field must be an array")
            return result
        
        if len(jwks['keys']) == 0:
            result['warnings'].append("JWKS contains no keys")
        
        # Validate each key
        required_fields = ['kty', 'kid']
        optional_fields = ['alg', 'use', 'key_ops']
        
        for i, key in enumerate(jwks['keys']):
            if not isinstance(key, dict):
                result['messages'].append(f"Key {i} must be a JSON object")
                continue
            
            # Check required fields
            for field in required_fields:
                if field not in key:
                    result['messages'].append(f"Key {i} missing required field '{field}'")
            
            # Validate key type
            kty = key.get('kty')
            if kty not in ['RSA', 'EC', 'oct']:
                result['warnings'].append(f"Key {i} has unknown key type '{kty}'")
            
            # Check for duplicate key IDs
            kid = key.get('kid')
            if kid:
                other_kids = [k.get('kid') for j, k in enumerate(jwks['keys']) if j != i]
                if kid in other_kids:
                    result['messages'].append(f"Duplicate key ID '{kid}' found")
            
            # Validate RSA keys
            if kty == 'RSA':
                rsa_fields = ['n', 'e']
                for field in rsa_fields:
                    if field not in key:
                        result['messages'].append(f"RSA key {i} missing required field '{field}'")
            
            # Validate EC keys
            elif kty == 'EC':
                ec_fields = ['crv', 'x', 'y']
                for field in ec_fields:
                    if field not in key:
                        result['messages'].append(f"EC key {i} missing required field '{field}'")
                
                # Check curve
                crv = key.get('crv')
                if crv not in ['P-256', 'P-384', 'P-521']:
                    result['warnings'].append(f"EC key {i} uses non-standard curve '{crv}'")
        
        # If no errors, mark as valid
        if not result['messages']:
            result['valid'] = True
            result['messages'].append(f"JWKS is valid with {len(jwks['keys'])} keys")
    
    except Exception as e:
        result['messages'].append(f"Validation error: {e}")
    
    return result

def jwks_info(jwks: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract information about a JWKS.
    
    Args:
        jwks (Dict[str, Any]): JWKS to analyze
        
    Returns:
        Dict[str, Any]: JWKS information
    """
    info = {
        'total_keys': len(jwks.get('keys', [])),
        'keys': []
    }
    
    for i, key in enumerate(jwks.get('keys', [])):
        key_info = {
            'index': i,
            'kid': key.get('kid', 'no-id'),
            'kty': key.get('kty', 'unknown'),
            'alg': key.get('alg', 'unspecified'),
            'use': key.get('use', 'unspecified'),
            'has_private': False
        }
        
        # Check if it's a private key
        if key.get('kty') == 'RSA':
            key_info['has_private'] = 'd' in key
        elif key.get('kty') == 'EC':
            key_info['has_private'] = 'd' in key
        elif key.get('kty') == 'oct':
            key_info['has_private'] = 'k' in key
        
        info['keys'].append(key_info)
    
    return info

def convert_jwks_to_public(jwks: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a JWKS to public-only by removing private key components.
    
    Args:
        jwks (Dict[str, Any]): Input JWKS
        
    Returns:
        Dict[str, Any]: Public-only JWKS
    """
    public_jwks = {
        'keys': []
    }
    
    private_components = ['d', 'dp', 'dq', 'p', 'q', 'qi', 'k']
    
    for key in jwks.get('keys', []):
        public_key = {k: v for k, v in key.items() if k not in private_components}
        public_jwks['keys'].append(public_key)
    
    return public_jwks

def main():
    parser = argparse.ArgumentParser(description='Key utilities for JWS keys')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Get information about a key')
    info_parser.add_argument('key_file', type=Path, help='Path to key file')
    
    # Convert command
    convert_parser = subparsers.add_parser('convert', help='Convert key format')
    convert_parser.add_argument('key_file', type=Path, help='Path to input key file')
    convert_parser.add_argument('--format', '-f', choices=['pem', 'der', 'base64'], 
                               required=True, help='Output format')
    convert_parser.add_argument('--output', '-o', type=Path, help='Output file (default: stdout)')
    
    # Validate command
    validate_parser = subparsers.add_parser('validate', help='Validate key for algorithm')
    validate_parser.add_argument('key_file', type=Path, help='Path to key file')
    validate_parser.add_argument('--algorithm', '-a', required=True,
                                choices=['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'],
                                help='JWS algorithm to validate against')
    
    # JWKS commands
    jwks_info_parser = subparsers.add_parser('jwks-info', help='Get information about a JWKS file')
    jwks_info_parser.add_argument('jwks_file', type=Path, help='Path to JWKS file')
    
    jwks_validate_parser = subparsers.add_parser('jwks-validate', help='Validate a JWKS file')
    jwks_validate_parser.add_argument('jwks_file', type=Path, help='Path to JWKS file')
    
    jwks_public_parser = subparsers.add_parser('jwks-public', help='Convert JWKS to public-only')
    jwks_public_parser.add_argument('jwks_file', type=Path, help='Path to input JWKS file')
    jwks_public_parser.add_argument('--output', '-o', type=Path, help='Output file (default: stdout)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == 'info':
            key = load_key_from_file(args.key_file)
            info = get_key_info(key)
            
            print(f"🔍 Key Information: {args.key_file}")
            print(f"   Type: {info['type']}")
            print(f"   Class: {info['key_class']}")
            
            if 'key_size' in info:
                print(f"   Key Size: {info['key_size']} bits")
            if 'curve' in info:
                print(f"   Curve: {info['curve']}")
            if 'public_exponent' in info:
                print(f"   Public Exponent: {info['public_exponent']}")
            
            if 'suggested_algorithms' in info and info['suggested_algorithms']:
                print(f"   Suggested Algorithms: {', '.join(info['suggested_algorithms'])}")
            
            if 'warning' in info:
                print(f"   ⚠️  Warning: {info['warning']}")
        
        elif args.command == 'convert':
            key = load_key_from_file(args.key_file)
            converted = convert_key_format(key, args.format)
            
            if args.output:
                with open(args.output, 'wb') as f:
                    f.write(converted)
                print(f"✅ Key converted to {args.format.upper()} format: {args.output}")
            else:
                print(converted.decode() if args.format == 'pem' else converted.decode())
        
        elif args.command == 'validate':
            key = load_key_from_file(args.key_file)
            result = validate_key_for_algorithm(key, args.algorithm)
            
            print(f"🔒 Validation Result: {args.key_file} for {args.algorithm}")
            print(f"   Valid: {'✅ Yes' if result['valid'] else '❌ No'}")
            
            for message in result['messages']:
                print(f"   - {message}")
        
        elif args.command == 'jwks-info':
            jwks = load_jwks_from_file(args.jwks_file)
            info = jwks_info(jwks)
            
            print(f"📋 JWKS Information: {args.jwks_file}")
            print(f"   Total Keys: {info['total_keys']}")
            print()
            
            for key_info in info['keys']:
                privacy = "Private" if key_info['has_private'] else "Public"
                print(f"   Key {key_info['index']+1}:")
                print(f"     ID: {key_info['kid']}")
                print(f"     Type: {key_info['kty']} ({privacy})")
                print(f"     Algorithm: {key_info['alg']}")
                print(f"     Use: {key_info['use']}")
                print()
        
        elif args.command == 'jwks-validate':
            jwks = load_jwks_from_file(args.jwks_file)
            result = validate_jwks(jwks)
            
            print(f"🔍 JWKS Validation: {args.jwks_file}")
            print(f"   Valid: {'✅ Yes' if result['valid'] else '❌ No'}")
            print()
            
            if result['messages']:
                print("   Messages:")
                for message in result['messages']:
                    print(f"     - {message}")
            
            if result['warnings']:
                print("   Warnings:")
                for warning in result['warnings']:
                    print(f"     ⚠️  {warning}")
        
        elif args.command == 'jwks-public':
            jwks = load_jwks_from_file(args.jwks_file)
            public_jwks = convert_jwks_to_public(jwks)
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(public_jwks, f, indent=2)
                print(f"✅ Public JWKS saved to {args.output}")
            else:
                print(json.dumps(public_jwks, indent=2))
    
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()