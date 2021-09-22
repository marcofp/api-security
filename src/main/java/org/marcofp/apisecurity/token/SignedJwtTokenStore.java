package org.marcofp.apisecurity.token;

import com.nimbusds.jose.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import spark.Request;

import java.text.ParseException;
import java.util.Date;
import java.util.Optional;

public class SignedJwtTokenStore implements AuthenticatedTokenStore {

    private final JWSSigner signer;
    private final JWSVerifier verifier;
    private final JWSAlgorithm algorithm;
    private final String audience;

    public SignedJwtTokenStore(JWSSigner signer, JWSVerifier verifier, JWSAlgorithm algorithm, String audience) {
        this.signer = signer;
        this.verifier = verifier;
        this.algorithm = algorithm;
        this.audience = audience;
    }

    @Override
    public String create(Request request, Token token) {

        // Create the JWT claims set with details about the token.
        var claimsSet = new JWTClaimsSet.Builder()
                .subject(token.username)
                .audience(audience)
                .expirationTime(Date.from(token.expiry))
                .claim("attrs", token.attributes)
                .build();

        // Specify the algorithm in the header and build the JWT.
        var header = new JWSHeader(JWSAlgorithm.HS256);
        var jwt = new SignedJWT(header, claimsSet);
        try {
            // Sign the JWT using the JWSSigner object.
            jwt.sign(signer);

            // Convert the signed JWT into the JWS compact serialization.
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {

        try {
            // Parse the JWT
            var jwt = SignedJWT.parse(tokenId);

            // Verify the HMA signature using the JWSVerifier
            if (!jwt.verify(verifier)) {
                throw new JOSEException("Invalid signature");
            }

            var claims = jwt.getJWTClaimsSet();
            // Reject the token if the audience doesn’t contain your API’s base URI.
            if (!claims.getAudience().contains(audience)) {
                throw new JOSEException("Incorrect audience");
            }

            // Extract token attributes from the remaining JWT claims.
            var expiry = claims.getExpirationTime().toInstant();
            var subject = claims.getSubject();
            var token = new Token(expiry, subject);
            var attrs = claims.getJSONObjectClaim("attrs");
            attrs.forEach((key, value) ->
                    token.attributes.put(key, (String) value));

            return Optional.of(token);
        } catch (ParseException | JOSEException e) {
            return Optional.empty();
        }

    }

    @Override
    public void revoke(Request request, String tokenId) {

    }
}
