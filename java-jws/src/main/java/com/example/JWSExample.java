package com.example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.util.Date;

public class JWSExample {
    
    private static final String SECRET_KEY = "your-256-bit-secret-key-here-must-be-long-enough";
    
    public static String signJsonPayload(String payload) throws JOSEException {
        JWSSigner signer = new MACSigner(SECRET_KEY);
        
        JWSObject jwsObject = new JWSObject(
            new JWSHeader(JWSAlgorithm.HS256),
            new Payload(payload)
        );
        
        jwsObject.sign(signer);
        
        return jwsObject.serialize();
    }
    
    public static String verifyAndExtractPayload(String jwsString) throws Exception {
        JWSObject jwsObject = JWSObject.parse(jwsString);
        
        JWSVerifier verifier = new MACVerifier(SECRET_KEY);
        
        if (jwsObject.verify(verifier)) {
            return jwsObject.getPayload().toString();
        } else {
            throw new Exception("JWS signature verification failed");
        }
    }
    
    public static String createSignedJWT(String subject, String issuer) throws JOSEException {
        JWSSigner signer = new MACSigner(SECRET_KEY);
        
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .subject(subject)
            .issuer(issuer)
            .issueTime(new Date())
            .expirationTime(new Date(new Date().getTime() + 60 * 60 * 1000))
            .build();
        
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        signedJWT.sign(signer);
        
        return signedJWT.serialize();
    }
    
    public static void main(String[] args) {
        try {
            String jsonPayload = "{\"userId\":\"12345\",\"action\":\"transfer\",\"amount\":100.50}";
            
            System.out.println("Original JSON payload: " + jsonPayload);
            
            String signedPayload = signJsonPayload(jsonPayload);
            System.out.println("Signed JWS: " + signedPayload);
            
            String verifiedPayload = verifyAndExtractPayload(signedPayload);
            System.out.println("Verified payload: " + verifiedPayload);
            
            String jwt = createSignedJWT("user123", "example-issuer");
            System.out.println("Signed JWT: " + jwt);
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}