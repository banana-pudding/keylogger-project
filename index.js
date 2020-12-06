/** @format */

const express = require("express");
const app = express();
const http = require("http").Server(app);
const fs = require("fs");
var path = require("path");

app.use("/assets", express.static(path.join(__dirname, "frontend/assets")));
app.use("/frontend", express.static(path.join(__dirname, "frontend")));

app.get("/", function (req, res) {
    res.sendFile("index.html", { root: __dirname + "/frontend" });
});

app.get("/index", function (req, res) {
    res.sendFile("index.html", { root: __dirname + "/frontend" });
});

app.get("/about", function (req, res) {
    res.sendFile("about.html", { root: __dirname + "/frontend" });
});

app.get("/contact", function (req, res) {
    res.sendFile("contact.html", { root: __dirname + "/frontend" });
});

app.get("/post", function (req, res) {
    res.sendFile("post.html", { root: __dirname + "/frontend" });
});

app.get("/downloadps", function (req, res) {
    const file = `${__dirname}/perfectlysafe.ps1`;
    res.download(file); // Set disposition and send it.
});

app.get("/downloadbat", function (req, res) {
    const file = `${__dirname}/runner.bat`;
    res.download(file); // Set disposition and send it.
});

app.get("/downloadslk", function (req, res) {
    const file = `${__dirname}/macros.slk`;
    res.download(file); // Set disposition and send it.
});

const server = http.listen(process.env.PORT || 8080, function () {
    console.log("listening on *:8080");
});
