package org.marcofp.apisecurity.token;

import spark.Request;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Optional;

public class CookieTokenStore implements SecureTokenStore {

    @Override
    public String create(Request request, Token token) {
        // Create a new session cookie
        var session = request.session(false);
        if (session != null){
            // Preventing session fixation attacks
            session.invalidate();
        }
        session = request.session(true);

        //Store token attributes as attributes of the session cookie.
        session.attribute("username", token.username);
        session.attribute("expiry", token.expiry);
        session.attribute("attrs", token.attributes);

        return Base64url.encode(sha256(session.id()));
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        var session = request.session(false);
        if (session == null) {
            return Optional.empty();
        }

        var provided = Base64.getUrlDecoder().decode(tokenId);
        var computed = sha256(session.id());
        if (!MessageDigest.isEqual(computed, provided)) {
            return Optional.empty();
        }

        // Populate the Token object with the session attributes.
        var token = new Token(session.attribute("expiry"),
                session.attribute("username"));

        token.attributes.putAll(session.attribute("attrs"));

        return Optional.of(token);

    }

    @Override
    public void revoke(Request request, String tokenId) {
        // Verify the anti-CSRF token
        var session = request.session(false);
        if (session == null) return;

        var provided = Base64url.decode(tokenId);
        var computed = sha256(session.id());

        if (!MessageDigest.isEqual(computed, provided)) {
            return;
        }

        // Invalidate the session cookie.
        session.invalidate();

    }

    static byte[] sha256(String tokenId) {
        try {
            var sha256 = MessageDigest.getInstance("SHA-256");
            return sha256.digest(
                    tokenId.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

}
