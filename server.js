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

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    address: { type: String, required: true },
    password: { type: String, required: true },
    mobile_number: { type: String, required: true },
    sessionTokens: [{ type: String }]
});

// Use the 'User' collection inside the 'newDB' database
const User = mongoose.model('User', userSchema, 'User');

// Middleware for common successful response format
function sendResponse(req, res, next) {
    res.sendResponse = function (message, data) {
        res.json({
            success: true,
            message: message,
            data: data
        });
    };
    next();
}

// Register common successful response middleware
app.use(sendResponse);

// Middleware to check token and manage sessions
async function checkToken(req, res, next) {
    // Extract token from request cookies
    const token = req.cookies.token;

    try {
        if (!token) {
            // Allow requests without a token for logout route
            if (req.path === '/logout') {
                return next();
            }
            const err = new Error("Token is missing");
            err.status = 401;
            throw err;
        }

        // Decrypt token
        const decoded = jwt.verify(token, JWT_SECRET);

        // Find the user in the database
        const user = await User.findOne({ email: decoded.email });

        // Check if user exists
        if (!user) {
            const err = new Error("User not found");
            err.status = 401;
            throw err;
        }

        // Check if token matches any of the session tokens stored in the user's sessionTokens array
        if (!user.sessionTokens.includes(token)) {
            const err = new Error("Invalid token");
            err.status = 401;
            throw err;
        }

        // Store user details in request for further processing
        req.user = user;
        req.token = token; // Store token for logout
        next();
    } catch (err) {
        next(err);
    }
}

// Login route
app.post('/login', async (req, res, next) => {
    const { email, password } = req.body;

    try {
        // Check if email and password are provided
        if (!email || !password) {
            const err = new Error("Email and password are required");
            err.status = 400;
            throw err;
        }

        // Find the user in the database
        const user = await User.findOne({ email, password });
        if (!user) {
            const err = new Error("Invalid email or password");
            err.status = 401;
            throw err;
        }

        // Generate JWT token for authentication
        const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '1h' });

        // Append the new token to the user's session tokens array
        user.sessionTokens.push(token);

        // Save the updated user object
        await user.save();

        // Set a cookie with the token
        res.cookie('token', token, { httpOnly: true, expires: new Date(Date.now() + 3600000) });

        res.sendResponse('Login successful', { token, email: user.email });

    } catch (err) {
        next(err);
    }
});

// Logout route
app.post('/logout', checkToken, async (req, res, next) => {
    try {
        // Clear the token cookie
        res.clearCookie('token');

        console.log('User object:', req.user); // Log the user object

        // Check if the user object is valid
        if (!req.user) {
            console.log('No user logged in');
            const err = new Error("No user logged in");
            err.status = 401;
            throw err;
        }

        // Remove the token associated with the current session
        const index = req.user.sessionTokens.indexOf(req.token);
        if (index !== -1) {
            req.user.sessionTokens.splice(index, 1);
        }

        // Save the updated user object
        await req.user.save();

        // Send response with the email of the user who logged out
        res.sendResponse("Logout successful", { email: req.user.email });
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
            const err = new Error("All fields are required");
            err.status = 400;
            throw err;
        }

        if (name.length < 3) {
            const err = new Error("Name must be at least 3 characters long");
            err.status = 400;
            throw err;
        }

        // other validation checks...

        // Check if the email already exists in the database
        const emailExists = await User.findOne({ email });
        if (emailExists) {
            const err = new Error("Email already exists");
            err.status = 400;
            throw err;
        }

    } catch (err) {
        next(err);
    }

    // Create a new user
    const newUser = new User({ name, email, address, password, mobile_number });
    try {
        await newUser.save();
        res.sendResponse('User registered successfully', {});
    } catch (err) {
        next(err);
    }
});

// Route to fetch users with a given mobile number
app.post('/users', async (req, res, next) => {
    const { mobile_number } = req.body;

    try {
        // Validate mobile number format
        // Query to fetch users' names with the given mobile number
        const users = await User.find({ mobile_number });
        const names = users.map(user => user.name);
        res.sendResponse('Users fetched successfully', names);
    } catch (err) {
        return next(err);
    }
});

// Route to fetch all users (new API)
app.get('/all-users', checkToken, async (req, res, next) => {
    try {
        // Query to fetch all users
        const users = await User.find();
        res.sendResponse('All users fetched successfully', users);
    } catch (err) {
        return next(err);
    }
});


// Route to test successful connection
app.get('/test', (req, res) => {
    res.send('Connected successfully');
});

// Common error handling middleware
function errorHandler(err, req, res, next) {
    const errStatus = err.status || 500;
    const errMessage = err.message || "Something went wrong!!!";
    const log = `[${new Date().toISOString()}] ${errStatus} - ${errMessage} - ${req.originalUrl} - ${req.method}`;
    console.error(log);
    return res.status(errStatus).json({
        success: false,
        message: errMessage,
        data: []
    });
}

// Register common error handling middleware
app.use(errorHandler);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
})