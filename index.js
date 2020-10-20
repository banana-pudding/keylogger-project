const express = require("express");
const app = express();
const http = require("http").Server(app);

app.get("/", function (req, res) {
  res.send("test.html");
});

const server = http.listen(process.env.PORT || 8080, function () {
  console.log("listening on *:8080");
});
