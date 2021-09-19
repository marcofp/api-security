package org.marcofp.apisecurity;

import java.nio.file.*;

import org.marcofp.apisecurity.controller.SpaceController;
import org.dalesbred.*;
import org.dalesbred.result.EmptyResultException;
import org.h2.jdbcx.*;
import org.json.*;
import org.marcofp.apisecurity.controller.UserController;
import spark.Filter;
import spark.Request;
import spark.Response;
import spark.Spark;
import com.google.common.util.concurrent.*;


import static spark.Spark.*;


public class Main {

    public static void main(String... args) throws Exception {
        secure("localhost.p12", "changeit", null, null);

        var datasource = JdbcConnectionPool.create(
                "jdbc:h2:mem:natter", "natter", "password");
        var database = Database.forDataSource(datasource);
        createTables(database);

        JdbcConnectionPool.create(
                "jdbc:h2:mem:natter", "natter_api_user", "password");
        database = Database.forDataSource(datasource);


        var spaceController = new SpaceController(database);
        Spark.post("/spaces", spaceController::createSpace);
        post("/spaces/:spaceId/messages", spaceController::postMessage);

        var userController = new UserController(database);
        Spark.post("/users", userController::registerUser);

        var rateLimiter = RateLimiter.create(2.0d);

        final Filter rateLimiterFilter = ((request, response) -> {
            if (!rateLimiter.tryAcquire()) {
                response.header("Retry-After", "2");
                halt(429);
            }
        });


        final Filter contentFilter = (request, response) -> {
            if (request.requestMethod().equals("POST") && !"application/json".equals(request.contentType())) {
                halt(415, new JSONObject().put("error", "Only application/json supported").toString());
            }

        };
        before(rateLimiterFilter, contentFilter, userController::authenticate);

        after((request, response) -> {
            response.type("application/json");
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
