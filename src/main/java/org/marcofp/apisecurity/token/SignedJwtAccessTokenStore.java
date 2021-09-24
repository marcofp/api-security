package org.marcofp.apisecurity.token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import spark.Request;

import java.net.MalformedURLException;
import java.net.URI;
import java.text.ParseException;
import java.util.Optional;

public class SignedJwtAccessTokenStore implements SecureTokenStore {

    private final String expectedIssuer;
    private final String expectedAudience;
    private final JWSAlgorithm signatureAlgorithm;
    private final JWKSource<SecurityContext> jwkSource;

    public SignedJwtAccessTokenStore(String expectedIssuer, String expectedAudience,
                                     JWSAlgorithm signatureAlgorithm,
                                     URI jwkSetUri) throws MalformedURLException {
        this.expectedIssuer = expectedIssuer;
        this.expectedAudience = expectedAudience;
        this.signatureAlgorithm = signatureAlgorithm;
        this.jwkSource = new RemoteJWKSet<>(jwkSetUri.toURL());
    }


    @Override
    public String create(Request request, Token token) {
        throw new UnsupportedOperationException();
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        try {
            var verifier = new DefaultJWTProcessor<>();
            var keySelector = new JWSVerificationKeySelector<>(
                    signatureAlgorithm, jwkSource);
            verifier.setJWSKeySelector(keySelector);

            // Verify the signature first.
            var claims = verifier.process(tokenId, null);

            // Ensure the issuer and audience have expected values.
            if (!expectedIssuer.equals(claims.getIssuer())) {
                return Optional.empty();
            }
            if (!claims.getAudience().contains(expectedAudience)) {
                return Optional.empty();
            }

            // Extract the JWT subject and expiry time.
            var expiry = claims.getExpirationTime().toInstant();
            var subject = claims.getSubject();
            var token = new Token(expiry, subject);

            // The scope may be either a string or an array of strings.
            String scope;
            try {
                scope = claims.getStringClaim("scope");
            } catch (ParseException e) {
                scope = String.join(" ",
                        claims.getStringListClaim("scope"));
            }
            token.attributes.put("scope", scope);
            return Optional.of(token);
        } catch (ParseException | BadJOSEException | JOSEException e) {
            return Optional.empty();
        }


    }

    @Override
    public void revoke(Request request, String tokenId) {
        throw new UnsupportedOperationException();
    }
}
