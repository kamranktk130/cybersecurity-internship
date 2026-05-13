const winston = require('winston');

// ─── LOGGER SETUP (Week 3) ───────────────────────────────────────────────────
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => {
      return `[${timestamp}] ${level.toUpperCase()}: ${message}`;
    })
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'security.log' })
  ]
});

logger.info('Application started');

// ─── DEPENDENCIES (Week 2) ───────────────────────────────────────────────────
const express    = require('express');
const helmet     = require('helmet');
const bcrypt     = require('bcrypt');
const jwt        = require('jsonwebtoken');
const validator  = require('validator');
const rateLimit  = require('express-rate-limit');
const path       = require('path');

const app    = express();
const PORT   = 3000;
const SECRET = 'your-secret-key';

// In-memory user store (no database needed)
const users = [];

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── RATE LIMITER (brute force protection) ────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many attempts. Try again in 15 minutes.'
});

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────────────────────
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    logger.warn('Unauthorized access attempt - no token provided');
    return res.status(401).json({ message: 'Access denied. No token.' });
  }
  jwt.verify(token, SECRET, (err, user) => {
    if (err) {
      logger.warn('Invalid or expired token used');
      return res.status(403).json({ message: 'Invalid or expired token.' });
    }
    req.user = user;
    next();
  });
}

// ─── ROUTES ───────────────────────────────────────────────────────────────────

// REGISTER
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;

  // Validate inputs
  if (!username || !email || !password) {
    logger.warn('Registration failed - missing fields');
    return res.status(400).json({ message: 'All fields are required.' });
  }
  if (!validator.isAlphanumeric(username) || !validator.isLength(username, { min: 3, max: 20 })) {
    logger.warn(`Registration failed - invalid username: ${username}`);
    return res.status(400).json({ message: 'Username must be 3-20 alphanumeric characters.' });
  }
  if (!validator.isEmail(email)) {
    logger.warn(`Registration failed - invalid email: ${email}`);
    return res.status(400).json({ message: 'Invalid email address.' });
  }
  if (!validator.isLength(password, { min: 8 })) {
    logger.warn('Registration failed - password too short');
    return res.status(400).json({ message: 'Password must be at least 8 characters.' });
  }

  // Check duplicate
  const exists = users.find(u => u.email === validator.normalizeEmail(email));
  if (exists) {
    logger.warn(`Registration failed - email already exists: ${email}`);
    return res.status(400).json({ message: 'Email already registered.' });
  }

  // Hash password and save
  const hashedPassword = await bcrypt.hash(password, 10);
  const sanitizedEmail = validator.normalizeEmail(email);
  const sanitizedUsername = validator.escape(username);
  users.push({ username: sanitizedUsername, email: sanitizedEmail, password: hashedPassword });

  logger.info(`New user registered: ${sanitizedEmail}`);
  res.status(201).json({ message: 'Registration successful!' });
});

// LOGIN
app.post('/api/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    logger.warn('Login failed - missing email or password');
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  const sanitizedEmail = validator.normalizeEmail(email);
  const user = users.find(u => u.email === sanitizedEmail);

  if (!user) {
    logger.warn(`Login failed - user not found: ${sanitizedEmail}`);
    return res.status(401).json({ message: 'Invalid credentials.' });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    logger.warn(`Login failed - wrong password for: ${sanitizedEmail}`);
    return res.status(401).json({ message: 'Invalid credentials.' });
  }

  const token = jwt.sign({ email: user.email, username: user.username }, SECRET, { expiresIn: '1h' });
  logger.info(`User logged in successfully: ${sanitizedEmail}`);
  res.json({ message: 'Login successful!', token });
});

// PROTECTED PROFILE ROUTE
app.get('/api/profile', authenticateToken, (req, res) => {
  logger.info(`Profile accessed by: ${req.user.email}`);
  res.json({ message: 'Welcome to your profile!', user: req.user });
});

// ─── START SERVER ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  logger.info(`Server running on http://localhost:${PORT}`);
});