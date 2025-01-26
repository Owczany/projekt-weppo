import http from 'http';
import express from 'express';
import bodyParser from 'body-parser';
import fs from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';
import mongoose from 'mongoose';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import { error } from 'console';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
import multer from 'multer';

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/'); 
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname)); 
    },
});

const upload = multer({
    storage,
    fileFilter: (req, file, cb) => {
        const fileTypes = /jpeg|jpg|png|gif/;
        const extName = fileTypes.test(path.extname(file.originalname).toLowerCase());
        const mimeType = fileTypes.test(file.mimetype);

        if (extName && mimeType) {
            return cb(null, true);
        } else {
            cb(new Error('Only images are allowed!'));
        }
    },
});

const app = express();
app.set('view engine', 'ejs');
app.set('views', './views');
app.use('/uploads', express.static('uploads'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

mongoose.connect('mongodb://127.0.0.1:27017/sklep', {
    useNewUrlParser: true,
    useUnifiedTopology: true, 
}).then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

const userSchema = new mongoose.Schema({
    username: String,
    email: String,
    password: String,
    role: String,
})

const prodcutSchema = new mongoose.Schema({
    id: Number,
    name: String,
    description: String,
    photo: String,
    price: Number,
})

const orderSchema = new mongoose.Schema({
    id: Number,
    userID: Number,

})

const User = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', prodcutSchema);
const Order = mongoose.model('Order', orderSchema);

async function getProducts() {
    try {
        const products = await Product.find(); 
        return products; 
    } catch (error) {
        console.error('Error fetching products:', error);
        return []; 
    }
}



async function registerNewUser(username, email, password, role) {
    const user = new User({ username: username, email: email, password: password, role: role });
    await user.save();
    console.log('User added:', user);
}


async function validateUser(login, password) {
    // const data = await User.findOne();
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
        //res.send(`Welcome ${login}! Your role is ${role}.`);
        res.render('shop_page', { error: null, admin : role === "admin" })
    } else {
        res.redirect('/login');
    }
});

app.get('/admin', (req, res) => { 
    const { login, role } = req.cookies;
    if (role !== "admin") {
        res.send("Nie masz wystarczających uprawnień!");
    }
    else {
        res.render("admin");
    }
})

app.get('/admin/products', (req, res) => { 
    const { login, role } = req.cookies;
    if (role !== "admin") {
        res.send("Nie masz wystarczających uprawnień!");
    }
    else {
        res.render("admin_products");
    }
})

app.get('/admin/products/add', (req, res) => { 
    const { login, role } = req.cookies;
    if (role !== "admin") {
        res.send("Nie masz wystarczających uprawnień!");
    }
    else {
        res.render("add-product");
    }
})

app.post('/admin/products/add', upload.single('product-image'), async (req, res) => {
    try {
        const { 'product-name': name, price, description } = req.body;
        const photo = req.file ? `/uploads/${req.file.filename}` : null;

        if (!name || !price || !description || !photo) {
            return res.status(400).send('All fields are required.');
        }

        const productCount = await Product.countDocuments();

        const newProduct = new Product({
            id: productCount + 1,
            name,
            description,
            photo,
            price: parseFloat(price),
        });

        await newProduct.save();
        res.redirect('/admin/products');
    } catch (error) {
        console.error(error);
        res.status(500).send('An error occurred while adding the product.');
    }
});

app.get('/admin/users', (req, res) => { 
    const { login, role } = req.cookies;
    if (role !== "admin") {
        res.send("Nie masz wystarczających uprawnień!");
    }
    else {
        res.send("Work in progress...");
    }
})

app.get('/admin/baskets', (req, res) => { 
    const { login, role } = req.cookies;
    if (role !== "admin") {
        res.send("Nie masz wystarczających uprawnień!");
    }
    else {
        res.send("Work in progress...");
    }
})

// Testy do sprawdzania widoków
app.get('/shop', (req, res) => {
    res.render('shop_page', { error: null })
});

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.get('/register', (req, res) => {
    res.render('register', { error: null, email: null, username: null });
})

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await validateUser(username, password);

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
        const hashedPassword = await bcrypt.hash(password, 10); // Szyfrowanie hasła z salą (10 rund)
        // const hashedPassword = password // Szyfrowanie hasła z salą (10 rund)
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
console.log(await getProducts());
console.log("started");

// monogod --dbpath TwojaKolekcja
// monogosh
