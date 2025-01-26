import http from 'http';
import express from 'express';
import bodyParser from 'body-parser';
import fs from 'fs';
import path from 'path';
import mongoose, { mongo } from 'mongoose';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import { error } from 'console';

// Inicjalizacja Express
const app = express();
app.use(express.static('public'));
app.use(express.json());

mongoose.connect('mongodb://127.0.0.1:27017/sklep', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

// Kolekcja users 
const userSchema = new mongoose.Schema({
    username: String,
    email: String,
    password: String,
    role: String,
});

// Kolekcja products
const productSchema = new mongoose.Schema({
    id: Number,
    name: String,
    description: String,
    photo: String,
    price: Number,
});

// Kolekcja carts
const cartSchema = new mongoose.Schema({
    username: String,
    productID: Number,
    status: String,
});

const User = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', productSchema);
const Cart = mongoose.model('Cart', cartSchema)

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

async function validateUser(login, password) {
    try {
        // Znajdź użytkownika w MongoDB po loginie
        const user = await User.findOne({ username: login });

        // Jeśli użytkownik nie istnieje, zwróć null
        if (!user) {
            return null;
        }

        // Sprawdź, czy hasło jest poprawne
        const isPasswordValid = await bcrypt.compare(password, user.password);

        // Jeśli hasło jest nieprawidłowe, zwróć null
        if (!isPasswordValid) {
            console.log('Niepoprawne hasło logowania')
            return null;
        }

        // Zwróć informacje o użytkowniku (login i rola)
        return {
            login: user.username,
            role: user.role
        };
    } catch (error) {
        console.error('Błąd podczas walidacji użytkownika:', error);
        throw new Error('Błąd walidacji użytkownika');
    }
}

app.get('/', (req, res) => {
    const { login, role } = req.cookies;
    if (login && role) {
        res.send(`Welcome ${login}! Your role is ${role}.`);
    } else {
        res.redirect('/login');
    }
});

app.get('/add-product', (req, res) => {
    const { login, role } = req.cookies;
    if (login && role === 'ADMIN') {
        res.render('add-product');
    } else {
        res.redirect('/login');
    }
});

// Jak ma przbiegać renderowanie shopping card
app.get('/shopping-cart', async (req, res) => {
    const { login, role } = req.cookies;
    if (login && role) {
        try {
            const carts = await Cart.find({ username: login, status: "IN CART" });
            const products = []
            for (const cart of carts) {
                let product = await Product.findOne({ id: cart.productID });
                console.log(product)
                products.push(product)
            }

            res.render('shopping-cart', { login, products, carts });
        } catch (err) {
            console.error(err)
        }
    } else {
        res.redirect('/login');
    }
});


app.post('/cart/add', async (req, res) => {
    console.log('Otrzymane dane:', req.body); // Sprawdź, co dokładnie jest odbierane w req.body
    const { productId } = req.body;
    console.log('Otrzymane productId:', productId); // Sprawdź, czy productId jest undefined

    const { login } = req.cookies;

    if (!login) {
        return res.status(401).send({ message: 'Musisz być zalogowany, aby dodać produkt do koszyka.' });
    }

    if (!productId) {
        return res.status(400).send({ message: 'Nie podano ID produktu.' });
    }

    try {
        const product = await Product.findOne({ id: productId });
        if (!product) {
            return res.status(404).send({ message: 'Produkt nie istnieje.' });
        }

        const newCartItem = new Cart({
            username: login,
            productID: productId,
            status: 'IN CART'
        });

        await newCartItem.save();
        res.status(200).send({ message: 'Produkt został dodany do koszyka.' });
    } catch (error) {
        console.error('Błąd podczas dodawania produktu do koszyka:', error);
        res.status(500).send({ message: 'Wystąpił błąd podczas dodawania produktu do koszyka.' });
    }
});



// Usuwanie produktu z koszyka
app.post('/shopping-cart/delete', async (req, res) => {
    const { id } = req.body;

    if (!id) return res.status(400).send({ message: 'ID nie zostało podane.' });

    try {
        const result = await Cart.findByIdAndDelete(id);
        if (!result) return res.status(404).send({ message: 'Produkt nie został znaleziony.' });

        res.status(200).send({ message: 'Produkt został usunięty z koszyka.' });
    } catch (error) {
        console.error('Error deleting cart item:', error);
        res.status(500).send({ message: 'Wystąpił błąd podczas usuwania produktu.' });
    }
});

app.post('/shopping-cart/checkout', async (req, res) => {
    const { login } = req.cookies;

    if (!login) {
        return res.status(401).send({ message: 'Musisz być zalogowany, aby złożyć zamówienie.' });
    }

    try {
        // Aktualizacja statusu wszystkich produktów w koszyku użytkownika
        const result = await Cart.updateMany(
            { username: login, status: 'IN CART' }, // Znajdź produkty z koszyka
            { $set: { status: 'IN ORDER' } }       // Ustaw status na "IN ORDER"
        );

        if (result.modifiedCount === 0) {
            return res.status(400).send({ message: 'Brak produktów do zamówienia.' });
        }

        res.status(200).send({ message: 'Zamówienie zostało złożone.' });
    } catch (error) {
        console.error('Błąd podczas składania zamówienia:', error);
        res.status(500).send({ message: 'Wystąpił błąd podczas składania zamówienia.' });
    }
});


async function seedProducts() {
    const sampleProducts = [
        {
            id: 1,
            name: "BMW 8 Series",
            description: "Luxury car with modern design.",
            photo: "https://www.motortrend.com/uploads/sites/10/2023/10/2024-bmw-8-series-840i-gran-coupe-4wd-sedan-angular-front.png?w=768&width=768&q=75&format=webp",
            price: 75000,
        },
        {
            id: 2,
            name: "Audi A6",
            description: "High-performance car with a sleek finish.",
            photo: "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcT50K1eGe2rWpcLD5pF57zLFyfnkkrF_UqX7w&s",
            price: 60000,
        },
    ];

    try {
        await Product.insertMany(sampleProducts);
        console.log('Sample products added to database');
    } catch (error) {
        console.error('Error adding sample products:', error);
    }
}

app.get('/shop', async (req, res) => {
    try {
        const searchQuery = req.query.search || ''; // Pobierz parametr wyszukiwania z zapytania
        const regex = new RegExp(searchQuery, 'i'); // Stwórz wyrażenie regularne ignorujące wielkość liter
        const products = await Product.find({
            $or: [
                { name: regex },
                { description: regex }
            ]
        }); // Szukaj w nazwie lub opisie produktów

        const { login } = req.cookies; // Pobierz login użytkownika z ciasteczek
        res.render('shop_page', { products, login }); // Przekazanie produktów i loginu do widoku
    } catch (error) {
        console.error('Error fetching products:', error);
        res.status(500).send('Error fetching products');
    }
});

app.get('/product/:id', async (req, res) => {
    try {
        const productId = req.params.id; // Pobierz ID produktu z URL
        const product = await Product.findOne({ id: productId }); // Znajdź produkt w bazie danych

        if (!product) {
            return res.status(404).send('Produkt nie został znaleziony');
        }

        res.render('product_page', { product }); // Przekaż dane produktu do widoku
    } catch (error) {
        console.error('Błąd podczas ładowania produktu:', error);
        res.status(500).send('Wystąpił błąd podczas ładowania produktu.');
    }
});

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.get('/register', (req, res) => {
    res.render('register', { error: null, email: null, username: null });
})

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Poczekaj na wynik walidacji użytkownika
        const user = await validateUser(username, password);
        console.log(user)

        if (user) {
            // Ustawienie ciasteczek
            res.cookie('login', user.login, { httpOnly: true });
            res.cookie('role', user.role, { httpOnly: true });
            res.redirect('/');
        } else {
            // Wyświetlenie błędu w przypadku niepoprawnych danych logowania
            res.render('login', { error: 'Invalid username or password!' });
        }
    } catch (error) {
        // Obsługa błędów
        console.error('Error during login:', error);
        res.render('login', { error: 'An error occurred during login. Please try again.' });
    }
});

app.post("/register", async (req, res) => {
    const { email, username, password, confirmPassword } = req.body;

    // Sprawdzenie, czy hasła są takie same
    if (password !== confirmPassword) {
        return res.render("register", {
            error: "Passwords do not match",
            email,
            username
        });
    }

    try {
        // Sprawdzenie, czy email już istnieje
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.render("register", {
                error: "This email is already registered",
                email,
                username
            });
        }

        // Sprawdzenie, czy nazwa użytkownika już istnieje
        const existingUsername = await User.findOne({ username });
        if (existingUsername) {
            return res.render("register", {
                error: "Username is already taken",
                email,
                username
            });
        }

        // Haszowanie hasła
        const hashedPassword = await bcrypt.hash(password, 10);

        // Tworzenie nowego użytkownika
        registerNewUser(username, email, hashedPassword, "USER");

        res.redirect("/login");
    } catch (error) {
        console.error("Error during registration:", error);
        res.render("register", {
            error: "An error occurred during registration. Please try again.",
            email,
            username
        });
    }
});


http.createServer(app).listen(3000);
console.log("started");

// monogod --dbpath TwojaKolekcja
// monogosh
