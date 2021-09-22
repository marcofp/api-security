package org.marcofp.apisecurity.token;

import org.json.JSONException;
import org.json.JSONObject;
import spark.Request;

import java.time.Instant;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.UTF_8;

public class JsonTokenStore implements TokenStore {

    @Override
    public String create(Request request, Token token) {
        var json = new JSONObject();
        json.put("sub", token.username);
        json.put("exp", token.expiry.getEpochSecond());
        json.put("attrs", token.attributes);

        var jsonBytes = json.toString().getBytes(UTF_8);
        return Base64url.encode(jsonBytes);
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        try {
            var decoded = Base64url.decode(tokenId);
            var json = new JSONObject(new String(decoded, UTF_8));
            var expiry = Instant.ofEpochSecond(json.getInt("exp"));
            var username = json.getString("sub");
            var attrs = json.getJSONObject("attrs");

            var token = new Token(expiry, username);
            for (var key : attrs.keySet()) {
                token.attributes.put(key, attrs.getString(key));
            }

            return Optional.of(token);
        } catch (JSONException e) {
            return Optional.empty();
        }
    }

    @Override
    public void revoke(Request request, String tokenId) {
        // TODO
    }
}
