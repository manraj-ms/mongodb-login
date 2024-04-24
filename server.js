const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

// Secret key for JWT
const JWT_SECRET = 'randomkey';

// Connect to MongoDB and use the newDB database
mongoose.connect('mongodb://localhost:27017/newDB');
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => console.log('Connected to MongoDB database'));

// Define MongoDB schema and models
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    address: { type: String, required: true },
    password: { type: String, required: true },
    mobile_number: { type: String, required: true }
});

// Use the 'User' collection inside the 'newDB' database
const User = mongoose.model('User', userSchema, 'User');

// Variable to store active sessions
let activeSessions = [];

// Validate email format using regex
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Validate phone number format
function validatePhoneNumber(mobile_number) {
    const phoneRegex = /^9\d{9}$/;
    return phoneRegex.test(mobile_number);
}

// Validate password complexity
function validatePassword(password) {
    return password.length >= 7 && /[!@#$%^&*(),.?":{}|<>]/.test(password);
}

// Login route
app.post('/login', async (req, res, next) => {
    const { email, password } = req.body;

    try {
        // Check if email and password are provided
        if (!email || !password) {
            const error = new Error("Email and password are required");
            error.status = 400;
            throw error;
        }

        // Find the user in the database
        const user = await User.findOne({ email, password });
        if (!user) {
            const error = new Error("Invalid email or password");
            error.status = 401;
            throw error;
        }

        // Generate JWT token for authentication
        const token = jwt.sign({ email: user.email }, JWT_SECRET);

        // Set a cookie with the token
        res.cookie('token', token, { httpOnly: true }); 

        // Store token and email in active sessions
        activeSessions.push({ token, email: user.email });

        res.json({ message: 'Login successful', token, email: user.email });

    } catch (err) {
        next(err);
    }
});

// Logout route
app.post('/logout', async (req, res, next) => {
    try {
        // Extract the token from the request body or query parameters
        const token = req.body.token || req.query.token;

        // Check if token is provided
        if (!token) {
            const error = new Error("Token is required for logout");
            error.status = 400;
            throw error;
        }

        // Clear the token cookie
        res.clearCookie('token');

        // Find the session index with the provided token
        const sessionIndex = activeSessions.findIndex(session => session.token === token);

        // Check if session exists
        if (sessionIndex === -1) {
            const error = new Error("Session not found");
            error.status = 404;
            throw error;
        }

        // Remove session from active sessions
        const { email } = activeSessions.splice(sessionIndex, 1)[0];

        res.json({ message: "Logout successful", email });
    } catch (error) {
        next(error);
    }
});

// Registration route
app.post('/register', async (req, res, next) => {
    const { name, email, address, password, mobile_number } = req.body;


    try {
    // Validate input fields
    if (!name || !email || !address || !password || !mobile_number) {
        const error = new Error("All fields are required");
        error.status = 400;
        return next(error);
    }

    if (name.length < 3) {
        const error = new Error("Name must be at least 3 characters long");
        error.status = 400;
        return next(error);
    }

    if (!validateEmail(email)) {
        const error = new Error("Invalid email format");
        error.status = 400;
        return next(error);
    }

    if (address.length < 10) {
        const error = new Error("Address must be at least 10 characters long");
        error.status = 400;
        return next(error);
    }

    if (!validatePassword(password)) {
        const error = new Error("Password must be at least 7 characters long and contain at least one special character");
        error.status = 400;
        return next(error);
    }

    if (!validatePhoneNumber(mobile_number)) {
        const error = new Error("Invalid mobile number");
        error.status = 400;
        return next(error);
    }

    // Check if the email already exists in the database
    
        const emailExists = await User.findOne({ email });
        if (emailExists) {
            const error = new Error("Email already exists");
            error.status = 400;
            return next(error);
        }
    } catch (err) {
        return next(err);
    }

    // Create a new user
    const newUser = new User({ name, email, address, password, mobile_number });
    try {
        await newUser.save();
        res.json({ message: 'User registered successfully' });
    } catch (err) {
        return next(err);
    }
});

// Route to fetch users with a given mobile number
app.post('/users', async (req, res, next) => {
    const { mobile_number } = req.body;

    try {
    // Validate mobile number format
    if (!validatePhoneNumber(mobile_number)) {
        const error = new Error("Invalid mobile number format");
        error.status = 400;
        return next(error);
    }

    // Query to fetch users' names with the given mobile number
    
        const users = await User.find({ mobile_number });
        const names = users.map(user => user.name);
        res.json(names);
    } catch (err) {
        return next(err);
    }
});

// Route to test successful connection
app.get('/test', (req, res) => {
    res.send('Connected successfully');
});

// Custom error handling middleware
app.use((err, req, res, next) => {

    // Default error response
    let statusCode = err.status || 500;
    let errorMessage = err.message || "Internal server error";

    // Send error response with JSON content type
    res.status(statusCode).json({ error: `${statusCode} - ${errorMessage}` });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
