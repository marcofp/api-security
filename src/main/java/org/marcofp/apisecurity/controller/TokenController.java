package org.marcofp.apisecurity.controller;

import org.json.JSONObject;
import org.marcofp.apisecurity.token.SecureTokenStore;
import org.marcofp.apisecurity.token.TokenStore;
import spark.Filter;
import spark.Request;
import spark.Response;

import java.nio.charset.StandardCharsets;
import java.time.temporal.ChronoUnit;
import java.util.Set;

import static java.time.Instant.now;
import static spark.Spark.halt;


public class TokenController {

    private static final String DEFAULT_SCOPES =
            "create_space post_message read_message list_messages " +
                    "delete_message add_member";

    private final SecureTokenStore tokenStore;

    public TokenController(final SecureTokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    public JSONObject login(Request request, Response response) {
        String subject = request.attribute("subject");
        var expiry = now().plus(10, ChronoUnit.MINUTES);
        var token = new TokenStore.Token(expiry, subject);
        var scope = request.queryParamOrDefault("scope", DEFAULT_SCOPES);
        token.attributes.put("scope", scope);
        var tokenId = tokenStore.create(request, token);
        response.status(201);
        return new JSONObject().put("token", tokenId);
    }

    public JSONObject logout(Request request, Response response) {

        var tokenId = request.headers("Authorization");
        if (tokenId == null || !tokenId.startsWith("Bearer")) {
            throw new IllegalArgumentException("missing token header");
        }

        tokenId = tokenId.substring(7);

        tokenStore.revoke(request, tokenId);
        response.status(200);
        return new JSONObject();

    }

    public void validateToken(Request request, Response response) {
        var tokenId = request.headers("Authorization");
        if (tokenId == null || !tokenId.startsWith("Bearer ")) {
            return;
        }

        tokenId = tokenId.substring(7);

        tokenStore.read(request, tokenId).ifPresent(token -> {
            if (now().isBefore(token.expiry)) {
                request.attribute("subject", token.username);
                // Adds all attributes: scope, ....
                token.attributes.forEach(request::attribute);
            } else {
                response.header("WWW-Authenticate", "Bearer error=\"invalid_token\"," +
                        "error_description=\"Expired\"");
                halt(401);
            }
        });

    }

    public Filter requireScope(String method, String requiredScope) {
        return ((request, response) -> {
            // If the HTTP method doesn’t match, then ignore this rule.
            if (!method.equalsIgnoreCase(request.requestMethod()))
                return;

            var tokenScope = request.<String>attribute("scope");

            //If the token is unscoped, then allow all operations.
            if (tokenScope == null) return;

            // If the token scope doesn’t contain the required scope, then return a 403 Forbidden response.
            if (!Set.of(tokenScope.split(" "))
                    .contains(requiredScope)) {
                response.header("WWW-Authenticate",
                        "Bearer error=\"insufficient_scope\"," +
                                "scope=\"" + requiredScope + "\"");
                halt(403);
            }
        });
    }

    String addPkceChallenge(spark.Request request,
                            String authorizeRequest) throws Exception {

        var secureRandom = new java.security.SecureRandom();
        var encoder = java.util.Base64.getUrlEncoder().withoutPadding();

        // Create a random code verifier string
        var verifierBytes = new byte[32];
        secureRandom.nextBytes(verifierBytes);
        var verifier = encoder.encodeToString(verifierBytes);

        // Store the verifier in a session cookie or other local storage
        request.session(true).attribute("verifier", verifier);


        // Create a code challenge as the SHA-256 hash of the code verifier string
        var sha256 = java.security.MessageDigest.getInstance("SHA-256");
        var challenge = encoder.encodeToString(
                sha256.digest(verifier.getBytes(StandardCharsets.UTF_8)));

        // Include the code challenge in the redirect to the AS authorization endpoint
        return authorizeRequest +
                "&code_challenge=" + challenge + "&code_challenge_method=S256";

    }

}