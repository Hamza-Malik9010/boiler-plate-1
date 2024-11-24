import dotenv from 'dotenv';
import express from 'express';
import mongoose from 'mongoose';
import session from 'express-session';
import passport from 'passport';
import passportLocalMongoose from 'passport-local-mongoose';
import MongoStore from 'connect-mongo';
import rateLimit from express-rate-limit;
import helmet from 'helmet';



// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
const apiLimiter = rateLimit({
  windowMs: 1000 * 60 * 15, // 15 minutes
  max:100,
  message: "too many requests from this IP, please try again later." 
})

app.use(apiLimiter);
app.use(express.json());
app.use(helmet());

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI || 'mongodb://localhost:27017/Explorely')
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

// Define the User Schema
const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    profilePicture: { type: String }, // URL to the profile picture
    communities: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Community' }],
    savedPosts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Post' }],
  },
  { timestamps: true }
);

// Apply passport-local-mongoose plugin
userSchema.plugin(passportLocalMongoose);

// Remove sensitive fields when converting to JSON
userSchema.set('toJSON', {
  transform: (_, ret) => {
    delete ret.email;
    delete ret.salt;
    delete ret.hash;
    delete ret.__v;
  },
});

// Create User Model
const User = mongoose.model('User', userSchema);

// Define the Community Schema and Model
const communitySchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    mantra: { type: String },
    coverPhoto: { type: String }, // URL to the cover photo
    users: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    posts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Post' }],
  },
  { timestamps: true }
);

const Community = mongoose.model('Community', communitySchema);

// Define the Post Schema and Model
const postSchema = new mongoose.Schema(
  {
    content: { type: String, required: true },
    community: { type: mongoose.Schema.Types.ObjectId, ref: 'Community', required: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    comments: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Comment' }],
    likedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    dislikedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  },
  { timestamps: true }
);

const Post = mongoose.model('Post', postSchema);

// Define the Comment Schema and Model
const commentSchema = new mongoose.Schema(
  {
    content: { type: String, required: true },
    post: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    parentComment: { type: mongoose.Schema.Types.ObjectId, ref: 'Comment', default: null },
    replies: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Comment' }],
    likedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    dislikedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  },
  { timestamps: true }
);

const Comment = mongoose.model('Comment', commentSchema);

// Set up session store
const sessionStore = MongoStore.create({
  mongoUrl: process.env.MONGO_URI || 'mongodb://localhost:27017/Explorely',
  collectionName: 'sessions',
});

// Set up session
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'yourSecretKey',
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, // 1 day
    },
  })
);

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Configure Passport
passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// Routes

// Endpoint to check username availability
app.get('/check-username', async (req, res) => {
  const { username } = req.query;

  // Validate input length
  if (!username || username.length < 6) {
    return res.status(400).json({ message: 'Username must be at least 6 characters long.' });
  }

  // Check database for existing username
  const existingUser = await User.findOne({ username });
  if (existingUser) {
    return res.status(409).json({ message: 'Username is already taken.' });
  }

  res.status(200).json({ message: 'Username is available.' });
});

// Endpoint to check email availability
app.get('/check-email', async (req, res) => {
  const { email } = req.query;

  // Basic email format validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || !emailRegex.test(email)) {
    return res.status(400).json({ message: 'Invalid email format.' });
  }

  // Check database for existing email
  const existingEmail = await User.findOne({ email });
  if (existingEmail) {
    return res.status(409).json({ message: 'Email is already taken.' });
  }

  res.status(200).json({ message: 'Email is available.' });
});

// Register route
app.post('/register', async (req, res, next) => {
  const { email, name, username, password } = req.body;

  // Check if the email already exists
  const existingEmail = await User.findOne({ email });
  if (existingEmail) {
    return res.status(400).send({ message: 'Email already registered' });
  }

  // Check if the username already exists
  const existingUsername = await User.findOne({ username });
  if (existingUsername) {
    return res.status(400).send({ message: 'Username already taken' });
  }

  // Register the user
  const newUser = new User({ email, name, username });
  const registeredUser = await User.register(newUser, password);

  // Log the user in
  req.login(registeredUser, (err) => {
    if (err) {
      return next(err);
    }
    res.status(201).send({ message: 'Registration successful', user: registeredUser });
  });
});

// Login middleware
const loginMiddleware = (req, res, next) => {
  // Use passport's authenticate method with the 'local' strategy
  passport.authenticate('local', (err, user) => {
    if (err) {
      return next(err);
    }

    if (!user) {
      return res.status(401).send({ message: 'Invalid username or password' });
    }

    // Log the user in
    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }

      res.status(200).send({ message: 'Login successful', user });
    });
  })(req, res, next);
};

// Login route
app.post('/login', loginMiddleware);

// Logout route
app.post('/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.status(200).send({ message: 'Logout successful' });
  });
});

// Protected route
app.get('/protected', (req, res) => {
  if (req.isAuthenticated()) {
    res.status(200).send({ message: 'Welcome to the protected route!' });
  } else {
    res.status(401).send({ message: 'Unauthorized access' });
  }
});

// Error handling middleware (Express.js 5 automatically handles async errors)
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send({ message: 'Server Error', error: err.message });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});