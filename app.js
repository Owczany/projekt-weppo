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
app.use(express.urlencoded({ extended: true }));

function validateUser(login, password) {
    const data = fs.readFileSync(path.join(__dirname, 'prototype.csv'), 'utf8');
    const lines = data.split('\n');
    for (const line of lines) {
      const [storedLogin, storedPassword, role] = line.split(' ');
      if (storedLogin === login && storedPassword === password) {
        return { login: storedLogin, 
                 role : role };
      }
    }
    return null;
}

app.get('/', (req, res) => {
    const { login, role } = req.query;
    res.send(`Welcome ${login}! Your role is ${role}.`);
});

app.get('/login', (req, res) => {
    res.render('login', { error : null });
});

app.get('/register', (req, res) => {
    res.render('register', { error : null, email : null, username : null });
})

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = validateUser(username, password);

    if (user) {
        res.redirect(`/?login=${user.login}&role=${user.role}`); 
    } else {
        res.render('login', { error: 'User does not exist!' });
    }
});

app.post("/register", (req, res) => {
    const { email, username, password, confirmPassword } = req.body;

    // Walidacja - sprawdzenie zgodności haseł
    if (password !== confirmPassword) {
        return res.render("register", { 
            error : "Passwords do not match", 
            email : email, 
            username : username 
        });
    }

    // Sprawdzenie czy użytkownik już istnieje
    const filePath = path.join(__dirname, 'prototype.csv');
    const data = fs.readFileSync(filePath, 'utf8').split('\n').map(line => line.split(' '));

    const userExists = data.some(([existingUsername]) => existingUsername === username);
    if (userExists) {
        return res.render("register", { 
            error: "Username is already taken", 
            email : email, 
            username : username 
        });
    }

    // Zapisanie nowego użytkownika
    const newUser = `${username} ${password} user\n`;
    fs.appendFileSync(filePath, newUser);

    // Sukces - przekierowanie na stronę logowania
    res.redirect("/login");
});


http.createServer(app).listen(3000);
console.log("started");