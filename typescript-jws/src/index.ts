import { SignJWT, jwtVerify, JWTPayload } from 'jose';

const SECRET_KEY = new TextEncoder().encode('your-256-bit-secret-key-here-must-be-long-enough');

export async function signJsonPayload(payload: string): Promise<string> {
  const jwt = await new SignJWT({ data: payload })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(SECRET_KEY);
  
  return jwt;
}

export async function verifyAndExtractPayload(jws: string): Promise<string> {
  try {
    const { payload } = await jwtVerify(jws, SECRET_KEY);
    return (payload as any).data;
  } catch (error) {
    throw new Error(`JWS signature verification failed: ${error}`);
  }
}

export async function createSignedJWT(subject: string, issuer: string): Promise<string> {
  const jwt = await new SignJWT({ 
    sub: subject,
    userId: subject,
    role: 'user'
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setIssuer(issuer)
    .setSubject(subject)
    .setExpirationTime('1h')
    .sign(SECRET_KEY);
  
  return jwt;
}

export interface TransactionPayload {
  userId: string;
  action: string;
  amount: number;
}

async function main() {
  try {
    const jsonPayload = JSON.stringify({
      userId: "12345",
      action: "transfer",
      amount: 100.50
    });
    
    console.log('Original JSON payload:', jsonPayload);
    
    const signedPayload = await signJsonPayload(jsonPayload);
    console.log('Signed JWS:', signedPayload);
    
    const verifiedPayload = await verifyAndExtractPayload(signedPayload);
    console.log('Verified payload:', verifiedPayload);
    
    const jwt = await createSignedJWT('user123', 'example-issuer');
    console.log('Signed JWT:', jwt);
    
  } catch (error) {
    console.error('Error:', error);
  }
}

if (require.main === module) {
  main();
}