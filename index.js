const express = require("express");
const app = express();
const http = require("http").Server(app);

app.get("/", function (req, res) {
  res.sendFile("test.html", { root: __dirname });
});

const server = http.listen(process.env.PORT || 8080, function () {
  console.log("listening on *:8080");
});
