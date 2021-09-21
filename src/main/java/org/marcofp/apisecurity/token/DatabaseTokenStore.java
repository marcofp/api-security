package org.marcofp.apisecurity.token;

import org.dalesbred.Database;
import org.json.JSONObject;
import spark.Request;

import java.security.SecureRandom;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;

public class DatabaseTokenStore implements TokenStore {


    private final Database database;
    private final SecureRandom secureRandom;


    public DatabaseTokenStore(final Database database) {
        this.database = database;
        this.secureRandom = new SecureRandom();
    }

    @Override
    public String create(Request request, Token token) {
        var tokenId = randomId();
        var attrs = new JSONObject(token.attributes).toString();
        database.updateUnique("INSERT INTO " +
                        "tokens(token_id, user_id, expiry, attributes) " +
                        "VALUES(?, ?, ?, ?)", tokenId, token.username,
                token.expiry, attrs);
        return tokenId;
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        return database.findOptional(this::readToken,
                "SELECT user_id, expiry, attributes " +
                        "FROM tokens WHERE token_id = ?", tokenId);

    }

    @Override
    public void revoke(Request request, String tokenId) {
        database.update("DELETE FROM tokens WHERE token_id = ?",
                tokenId);
    }

    private String randomId() {
        var bytes = new byte[20];
        new SecureRandom().nextBytes(bytes);
        return Base64url.encode(bytes);
    }

    private Token readToken(ResultSet resultSet) throws SQLException {
        var username = resultSet.getString(1);
        var expiry = resultSet.getTimestamp(2).toInstant();
        var json = new JSONObject(resultSet.getString(3));
        var token = new Token(expiry, username);
        for (var key : json.keySet()) {
            token.attributes.put(key, json.getString(key));
        }
        return token;
    }


}
