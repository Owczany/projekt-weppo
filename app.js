var http = require('http');
var express = require('express');
var bodyParser = require('body-parser');
var fs = require('fs');
var path = require('path');
var app = express();

// TODO 
// Kornel: login i rola przekazywana w ciastku zamiast parametrów strony

app.set('view engine', 'ejs');
app.set('views', './views');
app.use(bodyParser.urlencoded({ extended: true }));

function validateUser(login, password) {
    const data = fs.readFileSync(path.join(__dirname, 'prototype.csv'), 'utf8');
    const lines = data.split('\n');
    for (const line of lines) {
      const [storedLogin, storedPassword, role] = line.split(' ');
      if (storedLogin === login && storedPassword === password) {
        return { login: storedLogin, role };
      }
    }
    return null;
}

app.get('/', (req, res) => {
    const { login, role } = req.query;
    res.send(`Welcome ${login}! Your role is ${role}.`);
});

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = validateUser(username, password);

    if (user) {
        res.redirect(`/?login=${user.login}`); 
    } else {
        res.render('login', { error: 'User does not exist!' });
    }
});

http.createServer(app).listen(3000);
console.log("started");