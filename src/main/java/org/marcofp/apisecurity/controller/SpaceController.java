package org.marcofp.apisecurity.controller;

import org.dalesbred.Database;
import org.json.*;
import spark.*;

import java.sql.SQLException;


public class SpaceController {

    private final Database database;

    public SpaceController(Database database) {
        this.database = database;
    }

    public JSONObject createSpace(Request request, Response response) {
        var json = new JSONObject(request.body());
        var spaceName = json.getString("name");
        if (spaceName.length() > 255) {
            throw new IllegalArgumentException("space name too long");
        }

        var owner = json.getString("owner");
        var subject = request.attribute("subject");
        if (!owner.equals(subject)) {
            throw new IllegalArgumentException(
                    "owner must match authenticated user");
        }


        return database.withTransaction(tx -> {
            var spaceId = database.findUniqueLong(
                    "SELECT NEXT VALUE FOR space_id_seq;");
            database.updateUnique(
                    "INSERT INTO spaces(space_id, name, owner) " +
                            "VALUES(?, ?, ?);", spaceId, spaceName, owner);

            response.status(201);
            response.header("Location", "/spaces/" + spaceId);
            return new JSONObject()
                    .put("name", spaceName)
                    .put("uri", "/spaces/" + spaceId);
        });
    }

    // Additional REST API endpoints not covered in the book:
    public JSONObject postMessage(Request request, Response response) {
        var spaceId = Long.parseLong(request.params(":spaceId"));
        var json = new JSONObject(request.body());
        var user = json.getString("author");
        if (!user.equals(request.attribute("subject"))) {
            throw new IllegalArgumentException(
                    "author must match authenticated user");
        }

        var message = json.getString("message");
        if (message.length() > 1024) {
            throw new IllegalArgumentException("message is too long");
        }

        return database.withTransaction(tx -> {
            var msgId = database.findUniqueLong(
                    "SELECT NEXT VALUE FOR msg_id_seq;");
            database.updateUnique(
                    "INSERT INTO messages(space_id, msg_id, msg_time," +
                            "author, msg_text) " +
                            "VALUES(?, ?, current_timestamp, ?, ?)",
                    spaceId, msgId, user, message);

            response.status(201);
            var uri = "/spaces/" + spaceId + "/messages/" + msgId;
            response.header("Location", uri);
            return new JSONObject().put("uri", uri);
        });
    }

}
