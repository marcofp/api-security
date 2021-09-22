package org.marcofp.apisecurity.token;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import spark.Request;

import javax.crypto.SecretKey;
import java.text.ParseException;
import java.util.Date;
import java.util.Optional;
import java.util.Set;

public class EncryptedJwtTokenStore implements SecureTokenStore {

    private final SecretKey encKey;
    private final DatabaseTokenStore tokenAllowlist;


    public EncryptedJwtTokenStore(SecretKey encKey, DatabaseTokenStore tokenAllowlist) {
        this.encKey = encKey;
        this.tokenAllowlist = tokenAllowlist;
    }

    @Override
    public String create(Request request, Token token) {

        var allowlistToken = new Token(token.expiry, token.username);
        var jwtId = tokenAllowlist.create(request, allowlistToken);


        // Build the JWT claims set.
        var claimsBuilder = new JWTClaimsSet.Builder()
                .jwtID(jwtId)
                .subject(token.username)
                .audience("https://localhost:4567")
                .expirationTime(Date.from(token.expiry));
        token.attributes.forEach(claimsBuilder::claim);

        // Create the JWE header and assemble the header and claims.
        var header = new JWEHeader(JWEAlgorithm.DIR,
                EncryptionMethod.A128CBC_HS256);
        var jwt = new EncryptedJWT(header, claimsBuilder.build());

        // Encrypt the JWT using the AES key in direct encryption mode.
        try {
            var encrypter = new DirectEncrypter(encKey);
            jwt.encrypt(encrypter);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        return jwt.serialize();
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        try {
            // Parse the encrypted JWT.
            var jwt = EncryptedJWT.parse(tokenId);

            // Decrypt and authenticate the JWT using the DirectDecrypter.
            var decryptor = new DirectDecrypter(encKey);
            jwt.decrypt(decryptor);

            var claims = jwt.getJWTClaimsSet();
            var jwtId = claims.getJWTID();
            if (tokenAllowlist.read(request, jwtId).isEmpty()) {
                return Optional.empty();
            }

            if (!claims.getAudience().contains("https://localhost:4567")) {
                return Optional.empty();
            }

            // Extract any claims from the JWT.
            var expiry = claims.getExpirationTime().toInstant();
            var subject = claims.getSubject();
            var token = new Token(expiry, subject);
            var ignore = Set.of("exp", "sub", "aud");
            for (var attr : claims.getClaims().keySet()) {
                if (ignore.contains(attr)) continue;
                token.attributes.put(attr, claims.getStringClaim(attr));
            }

            return Optional.of(token);
        } catch (ParseException | JOSEException e) {
            return Optional.empty();
        }
    }


    @Override
    public void revoke(Request request, String tokenId) {
        try {
            var jwt = EncryptedJWT.parse(tokenId);
            var decryptor = new DirectDecrypter(encKey);
            jwt.decrypt(decryptor);
            var claims = jwt.getJWTClaimsSet();
            tokenAllowlist.revoke(request, claims.getJWTID());
        } catch (ParseException | JOSEException e) {
            throw new IllegalArgumentException("invalid token", e);
        }
    }

}
