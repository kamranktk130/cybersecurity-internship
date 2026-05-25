require('dotenv').config();

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

// ─── DEPENDENCIES ─────────────────────────────────────────────────────────────
const express   = require('express');
const helmet    = require('helmet');
const bcrypt    = require('bcrypt');
const jwt       = require('jsonwebtoken');
const validator = require('validator');
const rateLimit = require('express-rate-limit');
const cors      = require('cors');
const path      = require('path');

const app    = express();
const PORT   = process.env.PORT   || 3000;
const SECRET = process.env.SECRET || 'fallback-secret';

// In-memory user store
const users = [];

// ─── WEEK 4: API KEY MIDDLEWARE ───────────────────────────────────────────────
const VALID_API_KEYS = [process.env.API_KEY];

function apiKeyAuth(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key || !VALID_API_KEYS.includes(key)) {
    logger.warn(`API key rejected - invalid or missing key from IP: ${req.ip}`);
    return res.status(401).json({ error: 'Unauthorized: Invalid or missing API key.' });
  }
  logger.info(`API key accepted - request from IP: ${req.ip}`);
  next();
}

// ─── WEEK 4: CORS CONFIGURATION ──────────────────────────────────────────────
const corsOptions = {
  origin: 'http://localhost:3000',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key'],
  credentials: true
};
app.use(cors(corsOptions));

// ─── WEEK 4: FAIL2BAN SIMULATION (Intrusion Detection) ───────────────────────
// Mimics real Fail2Ban behavior: tracks failed logins per IP,
// bans the IP automatically after too many failed attempts.
const bannedIPs     = new Map();
const failedAttempts = new Map();

const FAIL2BAN_MAX_RETRIES = 5;
const FAIL2BAN_BAN_TIME    = 10 * 60 * 1000; // 10 minutes
const FAIL2BAN_FIND_TIME   =  5 * 60 * 1000; //  5 minutes

function fail2banMiddleware(req, res, next) {
  const ip = req.ip;

  if (bannedIPs.has(ip)) {
    const banExpiry = bannedIPs.get(ip);
    if (Date.now() < banExpiry) {
      logger.warn(`Fail2Ban: Blocked request from BANNED IP: ${ip}`);
      return res.status(403).json({
        error: 'Your IP has been temporarily banned due to suspicious activity.'
      });
    } else {
      // Ban expired — lift the ban
      bannedIPs.delete(ip);
      failedAttempts.delete(ip);
      logger.info(`Fail2Ban: IP unbanned after timeout: ${ip}`);
    }
  }
  next();
}

function recordFailedAttempt(ip) {
  const now = Date.now();
  if (!failedAttempts.has(ip)) {
    failedAttempts.set(ip, []);
  }

  // Only count attempts within the time window
  const attempts = failedAttempts.get(ip).filter(t => now - t < FAIL2BAN_FIND_TIME);
  attempts.push(now);
  failedAttempts.set(ip, attempts);

  logger.warn(`Fail2Ban: Failed attempt ${attempts.length}/${FAIL2BAN_MAX_RETRIES} from IP: ${ip}`);

  if (attempts.length >= FAIL2BAN_MAX_RETRIES) {
    bannedIPs.set(ip, now + FAIL2BAN_BAN_TIME);
    logger.warn(`Fail2Ban: IP BANNED for 10 minutes: ${ip}`);
  }
}

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc:              ["'self'"],
        scriptSrc:               ["'self'"],
        scriptSrcAttr:           ["'none'"],
        styleSrc:                ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc:                 ["'self'", "https://fonts.gstatic.com"],
        imgSrc:                  ["'self'", "data:"],
        connectSrc:              ["'self'"],
        frameSrc:                ["'none'"],
        objectSrc:               ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    strictTransportSecurity: {
      maxAge:            31536000,
      includeSubDomains: true,
    },
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── RATE LIMITERS ────────────────────────────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many attempts. Try again in 15 minutes.'
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { error: 'Too many API requests. Try again in 15 minutes.' }
});

// ─── AUTH MIDDLEWARE (Week 2) ─────────────────────────────────────────────────
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

// REGISTER (Week 2)
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;

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

  const exists = users.find(u => u.email === validator.normalizeEmail(email));
  if (exists) {
    logger.warn(`Registration failed - email already exists: ${email}`);
    return res.status(400).json({ message: 'Email already registered.' });
  }

  const hashedPassword    = await bcrypt.hash(password, 10);
  const sanitizedEmail    = validator.normalizeEmail(email);
  const sanitizedUsername = validator.escape(username);
  users.push({ username: sanitizedUsername, email: sanitizedEmail, password: hashedPassword });

  logger.info(`New user registered: ${sanitizedEmail}`);
  res.status(201).json({ message: 'Registration successful!' });
});

// LOGIN (Week 2 + Week 4 Fail2Ban added) ──────────────────────────────────────
app.post('/api/login', loginLimiter, fail2banMiddleware, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    logger.warn('Login failed - missing email or password');
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  const sanitizedEmail = validator.normalizeEmail(email);
  const user = users.find(u => u.email === sanitizedEmail);

  if (!user) {
    recordFailedAttempt(req.ip); // ← Fail2Ban tracking
    logger.warn(`Login failed - user not found: ${sanitizedEmail}`);
    return res.status(401).json({ message: 'Invalid credentials.' });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    recordFailedAttempt(req.ip); // ← Fail2Ban tracking
    logger.warn(`Login failed - wrong password for: ${sanitizedEmail}`);
    return res.status(401).json({ message: 'Invalid credentials.' });
  }

  const token = jwt.sign(
    { email: user.email, username: user.username },
    SECRET,
    { expiresIn: '1h' }
  );
  logger.info(`User logged in successfully: ${sanitizedEmail}`);
  res.json({ message: 'Login successful!', token });
});

// PROTECTED PROFILE ROUTE (Week 2)
app.get('/api/profile', authenticateToken, (req, res) => {
  logger.info(`Profile accessed by: ${req.user.email}`);
  res.json({ message: 'Welcome to your profile!', user: req.user });
});

// WEEK 4: API KEY PROTECTED ROUTE ─────────────────────────────────────────────
app.get('/api/data', apiLimiter, apiKeyAuth, (req, res) => {
  logger.info(`Secure data accessed via API key from IP: ${req.ip}`);
  res.json({
    message: 'Secure API data accessed successfully.',
    data: {
      appName: 'Secure App',
      version: '4.0',
      status:  'protected'
    }
  });
});

// ─── START SERVER ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  logger.info(`Server running on http://localhost:${PORT}`);
});