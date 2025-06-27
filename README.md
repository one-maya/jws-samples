# JWS Samples Monorepo

This monorepo contains example projects demonstrating how to sign JSON payloads using JWS (JSON Web Signature) in four different programming languages: Java, TypeScript, Go, and Python.

## Project Structure

```
jws-samples/
├── java-jws/           # Java JWS examples using Nimbus JOSE + JWT
├── typescript-jws/     # TypeScript JWS examples using jose library
├── go-jws/            # Go JWS examples using golang-jwt
├── python-jws/        # Python JWS examples using PyJWT
├── scripts/           # Key generation utilities
├── package.json       # Root package.json for monorepo management
└── README.md          # This file
```

## What is JWS?

JSON Web Signature (JWS) is a standard (RFC 7515) for digitally signing JSON data. It provides a way to ensure the integrity and authenticity of JSON payloads by creating a signature that can be verified by recipients.

## Getting Started

### Prerequisites

- **Java**: JDK 11 or higher, Maven
- **TypeScript**: Node.js 16+, npm
- **Go**: Go 1.21 or higher
- **Python**: Python 3.8+, pip

### Installation

From the root directory:

```bash
# Install all dependencies
npm run install:all

# Or install individually
npm run install:typescript
npm run install:python
```

### Running Examples

#### Java Example
```bash
# Build and run
npm run run:java

# Or directly with Maven
cd java-jws
mvn compile exec:java -Dexec.mainClass="com.example.JWSExample"
```

#### TypeScript Example
```bash
# Run in development mode
npm run run:typescript

# Or build and run
cd typescript-jws
npm run build
npm start
```

#### Go Example
```bash
# Run directly
npm run run:go

# Or build and run
cd go-jws
go run main.go
```

#### Python Example
```bash
# Run directly
npm run run:python

# Or run with Python directly
cd python-jws
python main.py
```

### Building All Projects

```bash
# Build TypeScript project
npm run build

# Build Java project
npm run build:java

# Build Go project
npm run build:go

# Build Python project (compile check)
npm run build:python
```

### Testing

```bash
# Run tests for supported projects
npm test

# Run tests individually
npm run test:typescript
npm run test:java
npm run test:go
npm run test:python
```

## Key Generation

The `scripts/` directory contains Python utilities for generating secure cryptographic keys for all sample projects.

### Quick Start with Key Generation

1. **Install key generation dependencies:**
   ```bash
   cd scripts
   pip install -r requirements.txt
   ```

2. **Generate HMAC keys for symmetric signing:**
   ```bash
   python generate_hmac_key.py --all --output-dir keys
   ```

3. **Generate RSA/ECDSA key pairs for asymmetric signing:**
   ```bash
   python generate_asymmetric_keys.py --all --output-dir keys
   ```

### Available Key Generation Scripts

- **`generate_hmac_key.py`** - Generate HMAC keys (HS256, HS384, HS512)
- **`generate_asymmetric_keys.py`** - Generate RSA and ECDSA key pairs (RS256/384/512, ES256/384/512)
- **`key_utils.py`** - Key conversion, validation, and inspection utilities

### Generated Key Formats

Each script generates keys in multiple formats for different programming languages:
- **Universal formats**: JSON, PEM, DER, Base64
- **Language-specific formats**: Java, Python, Go, TypeScript with usage examples

### Example: Generate and Use Keys

```bash
# Generate HS256 key
cd scripts
python generate_hmac_key.py --algorithm HS256

# Generated files in keys/hs256/:
# - hs256_key.json (universal format)
# - hs256_key.java (Java format)
# - hs256_key.py (Python format)
# - hs256_key.go (Go format)
# - hs256_key.ts (TypeScript format)
```

See `scripts/README.md` for detailed documentation and security best practices.

## Example Usage

Each project demonstrates:

1. **Signing a JSON payload** - Converting JSON data into a JWS token
2. **Verifying and extracting payload** - Validating the signature and retrieving original data
3. **Creating signed JWTs** - Generating JSON Web Tokens with standard claims

### Sample Output

```
Original JSON payload: {"userId":"12345","action":"transfer","amount":100.5}
Signed JWS: eyJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcklkXCI6XCIxMjM0NVwiLFwiYWN0aW9uXCI6XCJ0cmFuc2ZlclwiLFwiYW1vdW50XCI6MTAwLjV9IiwiaWF0IjoxNzA5ODI2MzYwLCJleHAiOjE3MDk4Mjk5NjB9.signature
Verified payload: {"userId":"12345","action":"transfer","amount":100.5}
Signed JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiaXNzIjoiZXhhbXBsZS1pc3N1ZXIiLCJpYXQiOjE3MDk4MjYzNjAsImV4cCI6MTcwOTgyOTk2MH0.signature
```

## Security Notes

⚠️ **Important**: The examples use a hardcoded secret key for demonstration purposes. In production:

- Use environment variables or secure key management systems
- Generate cryptographically secure random keys
- Implement proper key rotation
- Use appropriate key lengths (256-bit minimum for HMAC)

## Project Details

### Java (java-jws/)
- **Library**: Nimbus JOSE + JWT
- **Build Tool**: Maven
- **Java Version**: 11+
- **Key Features**: JWT creation, JWS signing/verification

### TypeScript (typescript-jws/)
- **Library**: jose
- **Build Tool**: npm/TypeScript
- **Node Version**: 16+
- **Key Features**: Async/await patterns, TypeScript interfaces

### Go (go-jws/)
- **Library**: golang-jwt/jwt
- **Build Tool**: go modules
- **Go Version**: 1.21+
- **Key Features**: Struct-based claims, error handling

### Python (python-jws/)
- **Library**: PyJWT
- **Build Tool**: pip/setuptools
- **Python Version**: 3.8+
- **Key Features**: Object-oriented design, comprehensive error handling, datetime utilities

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see individual project files for details.