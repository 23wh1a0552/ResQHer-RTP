const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcrypt');
const session = require('express-session');
const app = express();
const PORT = 3000;

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'project'
});

db.connect((err) => {
    if (err) {
        console.error('Database connection failed: ' + err.stack);
        process.exit(1);
        return;
    }
    console.log('Connected to database');
});

app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(bodyParser.json({ limit: '10mb' }));

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

app.post('/register', async (req, res) => {
    console.log("Received POST request to /register");
    console.log("Request Headers:", req.headers);
    console.log("Request Body:", req.body);

    if (!req.body || Object.keys(req.body).length === 0) {
        return res.status(400).json({ message: 'Request body is empty or not properly formatted.' });
    }

    const {
        fullName,
        email,
        password,
        phone,
        emergencyName1,
        emergencyPhone1,
        emergencyName2,
        emergencyPhone2
    } = req.body;

    try {
        if (!fullName || !fullName.trim() ||
            !email || !email.trim() ||
            !password || !password.trim() ||
            !phone || !phone.trim() ||
            !emergencyName1 || !emergencyName1.trim() ||
            !emergencyPhone1 || !emergencyPhone1.trim() ||
            !emergencyName2 || !emergencyName2.trim() ||
            !emergencyPhone2 || !emergencyPhone2.trim()) {
            return res.status(422).json({ message: 'Missing required fields.' });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(422).json({ message: 'Invalid email format.' });
        }

        const phoneRegex = /^\d{10}$/;
        if (!phoneRegex.test(phone) ||
            !phoneRegex.test(emergencyPhone1) ||
            !phoneRegex.test(emergencyPhone2)) {
            return res.status(422).json({ message: 'Invalid phone number format.' });
        }

        if (fullName.length > 255) {
            return res.status(422).json({ message: 'Full name is too long.' });
        }

        const [emailRows] = await db.promise().query('SELECT * FROM women_safety_registrations WHERE email = ?', [email]);
        if (emailRows.length > 0) {
            return res.status(409).json({ message: 'Email already exists.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const sql = `
            INSERT INTO women_safety_registrations
            (fullName, email, password, phone, emergencyName1, emergencyPhone1, emergencyName2, emergencyPhone2)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `;

        const [results] = await db.promise().query(sql, [
            fullName,
            email,
            hashedPassword,
            phone,
            emergencyName1,
            emergencyPhone1,
            emergencyName2,
            emergencyPhone2
        ]);

        console.log("Database insert successful", results);
        res.status(201).json({ message: 'Registration successful!' });
    } catch (err) {
        console.error('Error registering user:', err);
        res.status(500).json({ message: 'Server error during registration: ' + err.message });
    }
});

app.post('/login', async (req, res) => {
    console.log("Received POST request to /login");
    console.log("Request Headers:", req.headers);
    console.log("Request Body:", req.body);

    if (!req.body || Object.keys(req.body).length === 0) {
        return res.status(400).json({ message: 'Request body is empty or not properly formatted.' });
    }

    const { email, password } = req.body;

    try {
        if (!email || !email.trim() || !password || !password.trim()) {
            return res.status(422).json({ message: 'Missing email or password.' });
        }

        const [users] = await db.promise().query('SELECT * FROM women_safety_registrations WHERE email = ?', [email]);

        if (users.length === 0) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const user = users[0];

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (passwordMatch) {
            req.session.userId = user.id;
            console.log("Login successful. Session ID:", req.session.id, "User ID:", user.id);
            return res.json({ message: 'Login successful', redirect: '/dashboard' });
        } else {
            return res.status(401).json({ message: 'Invalid email or password' });
        }
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Server error during login: ' + error.message });
    }
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.post('/test', (req, res) => {
    console.log("Test Request Body:", req.body);
    res.json(req.body);
});

app.use((req, res) => {
    res.status(404).json({ message: 'Route not found' });
});

app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`);
});