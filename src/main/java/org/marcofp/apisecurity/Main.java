package org.marcofp.apisecurity;

import com.google.common.util.concurrent.RateLimiter;
import org.dalesbred.Database;
import org.dalesbred.result.EmptyResultException;
import org.h2.jdbcx.JdbcConnectionPool;
import org.json.JSONException;
import org.json.JSONObject;
import org.marcofp.apisecurity.controller.*;
import org.marcofp.apisecurity.token.CookieTokenStore;
import org.marcofp.apisecurity.token.TokenStore;
import spark.Request;
import spark.Response;
import spark.Spark;

import java.nio.file.Files;
import java.nio.file.Paths;

import static spark.Spark.*;


public class Main {

    public static void main(String... args) throws Exception {
        staticFiles.location("/public");
        secure("localhost.p12", "changeit", null, null);

        var datasource = JdbcConnectionPool.create(
                "jdbc:h2:mem:natter", "natter", "password");
        var database = Database.forDataSource(datasource);
        createTables(database);
        JdbcConnectionPool.create(
                "jdbc:h2:mem:natter", "natter_api_user", "password");
        database = Database.forDataSource(datasource);

        var spaceController = new SpaceController(database);
        var userController = new UserController(database);
        var auditController = new AuditController(database);
        var moderatorController = new ModeratorController(database);
        var tokenStore = new CookieTokenStore();
        var tokenController = new TokenController(tokenStore);

        var rateLimiter = RateLimiter.create(2.0d);

        before((request, response) -> {
            if (!rateLimiter.tryAcquire()) {
                response.header("Retry-After", "2");
                halt(429);
            }
        });

        before((request, response) -> {
            if (request.requestMethod().equals("POST") && !"application/json".equals(request.contentType())) {
                halt(415, new JSONObject().put("error", "Only application/json supported").toString());
            }

        });

        afterAfter((request, response) -> {
            response.type("application/json;charset=utf-8");
            response.header("X-Content-Type-Options", "nosniff");
            response.header("X-Frame-Options", "DENY");
            response.header("X-XSS-Protection", "0");
            response.header("Cache-Control", "no-store");
            response.header("Content-Security-Policy",
                    "default-src 'none'; frame-ancestors 'none'; sandbox");
            response.header("Server", "");
        });

        before(userController::authenticate);
        before(tokenController::validateToken);

        before(auditController::auditRequestStart);
        afterAfter(auditController::auditRequestEnd);

        before("/sessions", userController::requireAuthentication);
        post("/sessions", tokenController::login);

        delete("/sessions", tokenController::logout);

        before("/spaces", userController::requireAuthentication);
        post("/spaces", spaceController::createSpace);

        before("/spaces/:spaceId/messages", userController.requirePermission("POST", "w"));
        post("/spaces/:spaceId/messages", spaceController::postMessage);

        before("/spaces/:spaceId/messages/*",
                userController.requirePermission("GET", "r"));
        get("/spaces/:spaceId/messages/:msgId", spaceController::readMessage);

        before("/spaces/:spaceId/messages",
                userController.requirePermission("GET", "r"));
        get("/spaces/:spaceId/messages", spaceController::findMessages);

        before("/spaces/:spaceId/messages/*",
                userController.requirePermission("DELETE", "d"));
        delete("/spaces/:spaceId/messages/:msgId", moderatorController::deletePost);

        before("/spaces/:spaceId/members",
                userController.requirePermission("POST", "rwd"));
        post("/spaces/:spaceId/members", spaceController::addMember);


        post("/users", userController::registerUser);
        get("/logs", auditController::readAuditLog);


        internalServerError(new JSONObject()
                .put("error", "internal server error").toString());
        notFound(new JSONObject()
                .put("error", "not found").toString());
        exception(IllegalArgumentException.class, Main::badRequest);
        exception(JSONException.class, Main::badRequest);
        exception(EmptyResultException.class,
                (e, request, response) -> response.status(404));

    }

    private static void createTables(Database database)
            throws Exception {

        var path = Paths.get(
                Main.class.getResource("/schema.sql").toURI());
        database.update(Files.readString(path));
    }

    private static void badRequest(Exception ex, Request request, Response response) {
        response.status(400);
        response.body(new JSONObject()
                .put("error", ex.getMessage()).toString());
    }


}
