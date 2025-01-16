var http = require('http');
var express = require('express');
var bodyParser = require('body-parser');
var fs = require('fs');
var path = require('path');
var cookieParser = require('cookie-parser'); 
var app = express();



app.set('view engine', 'ejs');
app.set('views', './views');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser()); 

function validateUser(login, password) {
    const data = fs.readFileSync(path.join(__dirname, 'user-password-role.csv'), 'utf8');
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
    const { login, role } = req.cookies;
    if (login && role) {
        res.send(`Welcome ${login}! Your role is ${role}.`);
    } else {
        res.redirect('/login');
    }});

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
        res.cookie('login', user.login, { httpOnly: true }); 
        res.cookie('role', user.role, { httpOnly: true });  
        res.redirect('/');    
    } else {
        res.render('login', { error: 'User does not exist!' });
    }
});

app.post("/register", (req, res) => {
    const { email, username, password, confirmPassword } = req.body;

    if (password !== confirmPassword) {
        return res.render("register", { 
            error : "Passwords do not match", 
            email : email, 
            username : username 
        });
    }

    const filePath = path.join(__dirname, 'user-password-role.csv');
    const filePathMails = path.join(__dirname, 'user-mail.csv');
    const data = fs.readFileSync(filePath, 'utf8').split('\n').map(line => line.split(' '));
    const dataMail = fs.readFileSync(filePathMails, 'utf8').split('\n').map(line => line.split(' '));

    const userExists = data.some(([existingUsername]) => existingUsername === username);
    if (userExists) {
        return res.render("register", { 
            error: "Username is already taken", 
            email : email, 
            username : username 
        });
    }

    const mailExists = dataMail.some(([_, existingMail]) => existingMail === email);
    if (mailExists) {
        return res.render("register", { 
            error : "This email adress is already taken",
            email : email,
            username : username
        });
    }

    const newUser = `${username} ${password} user\n`;
    const newUserMail = `${username} ${email}\n`;
    fs.appendFileSync(filePath, newUser);
    fs.appendFileSync(filePathMails, newUserMail);

    res.redirect("/login");
});


http.createServer(app).listen(3000);
console.log("started");