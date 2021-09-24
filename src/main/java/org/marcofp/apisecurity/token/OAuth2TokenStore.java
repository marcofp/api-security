package org.marcofp.apisecurity.token;

import org.json.JSONObject;
import spark.Request;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.UTF_8;

public class OAuth2TokenStore implements SecureTokenStore {

    private final URI introspectionEndpoint;
    private final String authorization;
    private final HttpClient httpClient;

    public OAuth2TokenStore(URI introspectionEndpoint, String clientId, String clientSecret) {

        this.introspectionEndpoint = introspectionEndpoint;

        var credentials = URLEncoder.encode(clientId, UTF_8) + ":" +
                URLEncoder.encode(clientSecret, UTF_8);
        this.authorization = "Basic " + Base64.getEncoder()
                .encodeToString(credentials.getBytes(UTF_8));

        var sslParams = new SSLParameters();
        // Allow only TLS 1.2 and 1.3
        sslParams.setProtocols(new String[]{"TLSv1.3", "TLSv1.2"});

        sslParams.setCipherSuites(new String[]{
                // Configure secure cipher suites for TLS 1.3
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                // Configure secure cipher suites for TLS 1.2
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        });

        sslParams.setUseCipherSuitesOrder(true);
        sslParams.setEndpointIdentificationAlgorithm("HTTPS");

        try {
            // The SSLContext should be configured to trust only the CA used by the AS.
            var trustedCerts = KeyStore.getInstance("PKCS12");
            trustedCerts.load(
                    new FileInputStream("as.example.com.ca.p12"),
                    "password".toCharArray());
            var tmf = TrustManagerFactory.getInstance("PKIX");
            tmf.init(trustedCerts);
            var sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);
//            this.httpClient = HttpClient.newBuilder()
//                            .sslParameters(sslParams)
//                            .sslContext(sslContext)
//                            .build();
            this.httpClient = HttpClient.newHttpClient();

        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String create(Request request, Token token) {
        throw new UnsupportedOperationException();

    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        // Firstly, validate the token
        if (!tokenId.matches("[\\x20-\\x7E]{1,1024}")) {
            return Optional.empty();
        }

        // Encode the token into the POST form body
        var form = "token=" + URLEncoder.encode(tokenId, UTF_8) +
                "&token_type_hint=access_token";

        // Call the introspection endpoint using your client credentials.
        var httpRequest = HttpRequest.newBuilder()
                .uri(introspectionEndpoint)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", authorization)
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();

        try {
            var httpResponse = httpClient.send(httpRequest,
                    HttpResponse.BodyHandlers.ofString());
            if (httpResponse.statusCode() == 200) {
                var json = new JSONObject(httpResponse.body());
                // Check that the token is still active.
                if (json.getBoolean("active")) {
                    return processResponse(json);
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
        return Optional.empty();
    }

    private Optional<Token> processResponse(JSONObject response) {
        var expiry = Instant.ofEpochSecond(response.getLong("exp"));
        var subject = response.getString("sub");
        var token = new Token(expiry, subject);
        token.attributes.put("scope", response.getString("scope"));
        token.attributes.put("client_id",
                response.optString("client_id"));
        return Optional.of(token);
    }


    @Override
    public void revoke(Request request, String tokenId) {
        throw new UnsupportedOperationException();
    }
}
