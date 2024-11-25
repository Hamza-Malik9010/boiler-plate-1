// app.js

// ----------------------- Importing Required Modules -----------------------
import dotenv from 'dotenv';
import express from 'express';
import mongoose from 'mongoose';
import session from 'express-session';
import passport from 'passport';
import passportLocal from 'passport-local';
import MongoStore from 'connect-mongo';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import path from 'path';
import { fileURLToPath } from 'url';

// ----------------------- Configuration Setup -----------------------

// Load environment variables from .env file
dotenv.config();

// Initialize Express app
const app = express();

// Define the port to run the server on
const PORT = process.env.PORT || 3000;

// For __dirname in ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ----------------------- Security Middlewares -----------------------

// Set various HTTP headers for app security
app.use(helmet());

// Rate Limiting to prevent brute-force attacks and abuse
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    message: "Too many requests from this IP, please try again after 15 minutes."
  }
});

// Apply rate limiting to all requests (Uncomment if needed)
app.use(apiLimiter);

// ----------------------- Body Parsing Middleware -----------------------

// Parse incoming JSON requests and put the parsed data in req.body
app.use(express.json());

// ----------------------- MongoDB Connection -----------------------

// Connect to MongoDB using Mongoose
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/ToDoApp', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch((err) => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1); // Exit process with failure
});

// ----------------------- Session Management -----------------------

// Configure MongoDB session store
const sessionStore = MongoStore.create({
  mongoUrl: process.env.MONGO_URI || 'mongodb://localhost:27017/ToDoApp',
  collectionName: 'sessions',
});

// Configure Express Session Middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'yourSecretKey', // Replace with your own secret
  resave: false, // Do not save session if unmodified
  saveUninitialized: false, // Do not create session until something stored
  store: sessionStore, // Use MongoDB to store session data
  cookie: {
    maxAge: 1000 * 60 * 60 * 24, // 1 day in milliseconds
    httpOnly: true, // Mitigate XSS attacks
    secure: process.env.NODE_ENV === 'production', // Ensure cookies are sent over HTTPS in production
    sameSite: 'lax', // CSRF protection
  },
}));

// ----------------------- Passport.js Configuration -----------------------

// Initialize Passport.js
app.use(passport.initialize());
app.use(passport.session());

// ----------------------- Define Your Schemas and Models -----------------------

// NOTE: Insert your Mongoose schemas and model definitions here.
// Example:
// import mongoose from 'mongoose';
// const userSchema = new mongoose.Schema({ /* ... */ });
// const User = mongoose.model('User', userSchema);
// passport.use(new LocalStrategy(User.authenticate()));
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

// ----------------------- Authentication Configuration -----------------------

// using passport-local strategy
const LocalStrategy = passportLocal.Strategy;
passport.use(new LocalStrategy(User.authenticate()));

// Serialize and deserialize user instances to and from the session
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// ----------------------- Custom Middlewares -----------------------

// Middleware to check if the user is authenticated
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ message: 'Unauthorized access. Please log in.' });
};

// ----------------------- Routes -----------------------

// Registration Route (Asynchronous)
app.post('/register', async (req, res, next) => {
  const { email, name, username, password } = req.body;

  // Check if the email already exists
  const existingEmail = await User.findOne({ email });
  if (existingEmail) {
    return res.status(400).json({ message: 'Email already registered.' });
  }

  // Check if the username already exists
  const existingUsername = await User.findOne({ username });
  if (existingUsername) {
    return res.status(400).json({ message: 'Username already taken.' });
  }

  // Register the new user
  const newUser = new User({ email, name, username });
  const registeredUser = await User.register(newUser, password);

  // Log the user in after registration
  req.login(registeredUser, (err) => {
    if (err) {
      // Pass error to the global error handler
      return next(err);
    }
    res.status(201).json({ message: 'Registration successful.', user: registeredUser });
  });
});

// Login Route (Asynchronous)
app.post('/login', passport.authenticate('local'), (req, res) => {
  res.status(200).json({ message: 'Login successful.', user: req.user });
});

// Logout Route (Synchronous)
app.post('/logout', (req, res, next) => {
  req.logout(function(err) {
    if (err) { 
      return next(err); 
    }
    res.status(200).json({ message: 'Logout successful.' });
  });
});

// ----------------------- Error Handling Middleware -----------------------

// Handle 404 Errors for undefined routes
app.use((req, res, next) => {
  res.status(404).json({ message: 'Resource not found.' });
});

// Global Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('🔴 Error:', err);
  res.status(err.status || 500).json({
    message: err.message || 'Internal Server Error',
    // In development, include stack trace for debugging
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
  });
});

// ----------------------- Start the Server -----------------------

app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);
});