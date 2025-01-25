import http from 'http';
import express from 'express';
import bodyParser from 'body-parser';
import fs from 'fs';
import path from 'path';
import mongoose from 'mongoose';
import cookieParser from 'cookie-parser';
// import bcrypt from 'bcrypt';
import { error } from 'console';

// Inicjalizacja Express
const app = express();

mongoose.connect('mongodb://127.0.0.1:27017/sklep', {
    useNewUrlParser: true,
    useUnifiedTopology: true, // Poprawiono literówkę
}).then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

const userSchema = new mongoose.Schema({
    username: String,
    email: String,
    password: String,
    role: String,
})

const prodcutSchema = new mongoose.Schema({
    name: String,
    description: String,
    photo: String,
    price: Number,
})

const User = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', prodcutSchema);

async function registerNewUser(username, email, password, role) {
    const user = new User({ username: username, email: email, password: password, role: role });
    await user.save();
    console.log('User added:', user);
}

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
        if (storedLogin === login && bcrypt.compareSync(password, storedPassword)) {
            return {
                login: storedLogin,
                role: role
            };
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
    }
});

// Testowow do sprawdzania widoków
app.get('/shop', (req, res) => {
    res.render('shop_page', { error: null })
});

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.get('/register', (req, res) => {
    res.render('register', { error: null, email: null, username: null });
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

app.post("/register", async (req, res) => {
    const { email, username, password, confirmPassword } = req.body;

    if (password !== confirmPassword) {
        return res.render("register", {
            error: "Passwords do not match",
            email: email,
            username: username
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
            email: email,
            username: username
        });
    }

    const mailExists = dataMail.some(([_, existingMail]) => existingMail === email);
    if (mailExists) {
        return res.render("register", {
            error: "This email adress is already taken",
            email: email,
            username: username
        });
    }

    try {
        // const hashedPassword = await bcrypt.hash(password, 10); // Szyfrowanie hasła z salą (10 rund)
        const hashedPassword = password // Szyfrowanie hasła z salą (10 rund)
        const newUser = `${username} ${hashedPassword} user\n`;
        fs.appendFileSync(filePath, newUser);
        const newUserMail = `${username} ${email}\n`;
        fs.appendFileSync(filePathMails, newUserMail);
        res.redirect("/login");
    } catch (error) {
        console.error("Error hashing password:", error);
        res.render("register", {
            error: "An error occurred during registration. Please try again.",
            email: email,
            username: username
        });
    }
});


http.createServer(app).listen(3000);
console.log("started");

