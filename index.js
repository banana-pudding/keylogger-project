/** @format */

const express = require("express");
const app = express();
const http = require("http").Server(app);
const fs = require("fs");

app.get("/", function (req, res) {
    res.sendFile("test.html", { root: __dirname });
});

app.get("/download", function (req, res) {
    const file = `${__dirname}/test.jpg`;
    res.download(file); // Set disposition and send it.
});

const server = http.listen(process.env.PORT || 8080, function () {
    console.log("listening on *:8080");
});
