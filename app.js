var http = require('http');
var express = require('express');
var app = express();

app.set('view engine', 'ejs');
app.set('views', './views');

app.get("/login", (req, res) => {
    res.render("login");
});

http.createServer(app).listen(3000);
console.log("started");