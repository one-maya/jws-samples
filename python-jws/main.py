#!/usr/bin/env python3
"""
Python JWS Example

This module demonstrates how to sign JSON payloads using JWS (JSON Web Signature)
and create/verify JWTs in Python using the PyJWT library.
"""

import json
import jwt
from datetime import datetime, timedelta
from typing import Dict, Any

SECRET_KEY = "your-256-bit-secret-key-here-must-be-long-enough"

def sign_json_payload(payload: str) -> str:
    """
    Sign a JSON payload using JWS.
    
    Args:
        payload (str): The JSON payload to sign
        
    Returns:
        str: The signed JWS token
    """
    claims = {
        "data": payload,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    
    token = jwt.encode(claims, SECRET_KEY, algorithm="HS256")
    return token

def verify_and_extract_payload(jws_token: str) -> str:
    """
    Verify a JWS token and extract the original payload.
    
    Args:
        jws_token (str): The JWS token to verify
        
    Returns:
        str: The original payload
        
    Raises:
        Exception: If signature verification fails
    """
    try:
        decoded = jwt.decode(jws_token, SECRET_KEY, algorithms=["HS256"])
        return decoded["data"]
    except jwt.InvalidTokenError as e:
        raise Exception(f"JWS signature verification failed: {e}")

def create_signed_jwt(subject: str, issuer: str) -> str:
    """
    Create a signed JWT with standard claims.
    
    Args:
        subject (str): The subject of the JWT
        issuer (str): The issuer of the JWT
        
    Returns:
        str: The signed JWT token
    """
    claims = {
        "sub": subject,
        "iss": issuer,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1),
        "userId": subject,
        "role": "user"
    }
    
    token = jwt.encode(claims, SECRET_KEY, algorithm="HS256")
    return token

def verify_jwt(jwt_token: str) -> Dict[str, Any]:
    """
    Verify and decode a JWT token.
    
    Args:
        jwt_token (str): The JWT token to verify
        
    Returns:
        Dict[str, Any]: The decoded claims
        
    Raises:
        Exception: If token verification fails
    """
    try:
        decoded = jwt.decode(jwt_token, SECRET_KEY, algorithms=["HS256"])
        return decoded
    except jwt.InvalidTokenError as e:
        raise Exception(f"JWT verification failed: {e}")

class TransactionPayload:
    """Data class for transaction payloads."""
    
    def __init__(self, user_id: str, action: str, amount: float):
        self.user_id = user_id
        self.action = action
        self.amount = amount
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "userId": self.user_id,
            "action": self.action,
            "amount": self.amount
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())

def main():
    """Main function demonstrating JWS usage."""
    try:
        # Create a sample transaction payload
        transaction = TransactionPayload("12345", "transfer", 100.50)
        json_payload = transaction.to_json()
        
        print(f"Original JSON payload: {json_payload}")
        
        # Sign the payload
        signed_payload = sign_json_payload(json_payload)
        print(f"Signed JWS: {signed_payload}")
        
        # Verify and extract the payload
        verified_payload = verify_and_extract_payload(signed_payload)
        print(f"Verified payload: {verified_payload}")
        
        # Create a signed JWT
        jwt_token = create_signed_jwt("user123", "example-issuer")
        print(f"Signed JWT: {jwt_token}")
        
        # Verify the JWT
        jwt_claims = verify_jwt(jwt_token)
        print(f"JWT claims: {json.dumps(jwt_claims, indent=2, default=str)}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()