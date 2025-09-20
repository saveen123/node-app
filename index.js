// app.js - Production-ready single-file Express 5 backend
require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const winston = require('winston');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const { v4: uuidv4 } = require('uuid');
const xss = require('xss-clean');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');
const crypto = require('crypto');

const app = express();

/* --------- Config & Logger --------- */
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

const logger = winston.createLogger({
  level: NODE_ENV === 'production' ? 'info' : 'debug',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => `${timestamp} ${level}: ${message}`)
  ),
  transports: [new winston.transports.Console()]
});

/* --------- DB Pool --------- */
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  database: process.env.DB_NAME,
  password: process.env.DB_PASS,
  port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

/* --------- Security Middlewares --------- */
app.use(helmet());
app.use(compression());
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(xss()); // XSS sanitize
app.use(mongoSanitize()); // sanitize mongodb-style operators (defensive)
app.use(hpp()); // prevent param pollution


app.use(cors());

// Logging requests via morgan -> winston
app.use(morgan('combined', { stream: { write: msg => logger.info(msg.trim()) } }));

// Rate limiter (global)
const limiter = rateLimit({
  windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS || 60_000),
  max: Number(process.env.RATE_LIMIT_MAX || 100),
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

/* --------- Secrets & Token Helpers --------- */
const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const ACCESS_EXPIRES = process.env.ACCESS_TOKEN_EXPIRES || '15m';
const REFRESH_DAYS = Number(process.env.REFRESH_TOKEN_EXPIRES_DAYS || 7);
const SALT_ROUNDS = Number(process.env.BCRYPT_SALT_ROUNDS || 12);

if (!ACCESS_SECRET || !REFRESH_SECRET) {
  logger.error('JWT secrets missing in env');
  process.exit(1);
}

function genAccess(payload) {
  return jwt.sign(payload, ACCESS_SECRET, { expiresIn: ACCESS_EXPIRES });
}
function genRefresh(payload) {
  // include a unique token id
  return jwt.sign({ ...payload, jti: uuidv4() }, REFRESH_SECRET, { expiresIn: `${REFRESH_DAYS}d` });
}

function hashTokenRaw(token) {
  // Use sha256 hex representation for storage comparison (fast and non-reversible)
  return crypto.createHash('sha256').update(token).digest('hex');
}

function getExpiryDateDays(days) {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString().slice(0, 19).replace('T', ' ');
}

/* --------- Validation Schemas (Joi) --------- */
const registerSchema = Joi.object({
  username: Joi.string().min(3).max(150).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(8).max(128).required()
});
const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});
const changePwdSchema = Joi.object({
  oldPassword: Joi.string().required(),
  newPassword: Joi.string().min(8).max(128).required()
});
const requestResetSchema = Joi.object({ email: Joi.string().email().required() });
const resetSchema = Joi.object({ token: Joi.string().required(), newPassword: Joi.string().min(8).max(128).required() });

/* --------- Helper responses --------- */
const json = (res, status, payload) => res.status(status).json(payload);

/* --------- Auth middlewares --------- */
async function authenticate(req, res, next) {
  try {
    const header = req.headers['authorization'] || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return json(res, 401, { message: 'Missing access token' });

    const payload = jwt.verify(token, ACCESS_SECRET);
    req.user = payload; // { id, email, role, iat, exp }
    return next();
  } catch (err) {
    return json(res, 403, { message: 'Invalid or expired access token' });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return json(res, 401, { message: 'Unauthenticated' });
    if (req.user.role !== role) return json(res, 403, { message: 'Forbidden' });
    next();
  };
}

/* --------- Routes --------- */

// Health
app.get('/', (req, res) => res.json({ status: 'ok', env: NODE_ENV }));

/* Register */
app.post('/auth/register', async (req, res) => {
  const { error, value } = registerSchema.validate(req.body);
  if (error) return json(res, 400, { message: error.message });

  const { username, email, password } = value;
  // check existing
  const [exists] = await db.execute('SELECT id FROM `user` WHERE email = ? LIMIT 1', [email]);
  if (exists.length) return json(res, 409, { message: 'Email already registered' });

  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  const [resInsert] = await db.execute('INSERT INTO `user` (username, email, password) VALUES (?, ?, ?)', [username, email, hash]);

  logger.info(`New user created id=${resInsert.insertId} email=${email}`);
  return json(res, 201, { message: 'Registered', userId: resInsert.insertId });
});

/* Login */
app.post('/auth/login', async (req, res) => {
  const { error, value } = loginSchema.validate(req.body);
  if (error) return json(res, 400, { message: error.message });

  const { email, password } = value;
  const [rows] = await db.execute('SELECT id, username, email, password, role FROM `user` WHERE email = ? LIMIT 1', [email]);
  const user = rows[0];
  if (!user) return json(res, 400, { message: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return json(res, 400, { message: 'Invalid credentials' });

  // Minimal payload
  const payload = { id: user.id, email: user.email, role: user.role };

  const accessToken = genAccess(payload);
  const refreshToken = genRefresh({ id: user.id }); // signed contains jti
  const refreshHash = hashTokenRaw(refreshToken);
  const expiresAt = getExpiryDateDays(REFRESH_DAYS);

  // Store hashed refresh token (not raw)
  await db.execute('INSERT INTO refresh_token (user_id, token_hash, expires_at) VALUES (?, ?, ?)', [user.id, refreshHash, expiresAt]);

  // Set refresh cookie
  const cookieOpts = {
    httpOnly: true,
    sameSite: 'strict',
    secure: NODE_ENV === 'production',
    path: '/auth/refresh',
    maxAge: REFRESH_DAYS * 24 * 60 * 60 * 1000
  };
  res.cookie('refreshToken', refreshToken, cookieOpts);

  logger.info(`User login id=${user.id} email=${user.email}`);
  return json(res, 200, { accessToken, user: { id: user.id, username: user.username, email: user.email, role: user.role } });
});

/* Refresh - rotates refresh tokens */
app.post('/auth/refresh', async (req, res) => {
  try {
    const token = req.cookies.refreshToken;
    if (!token) return json(res, 401, { message: 'No refresh token' });

    let payload;
    try {
      payload = jwt.verify(token, REFRESH_SECRET);
    } catch (err) {
      return json(res, 403, { message: 'Invalid refresh token' });
    }

    const tokenHash = hashTokenRaw(token);
    const [rows] = await db.execute('SELECT * FROM refresh_token WHERE token_hash = ? LIMIT 1', [tokenHash]);
    const row = rows[0];
    if (!row || row.revoked) return json(res, 403, { message: 'Refresh token revoked or not found' });

    // rotation: revoke old token
    await db.execute('UPDATE refresh_token SET revoked=1 WHERE id = ?', [row.id]);

    // Issue new tokens
    const [userRows] = await db.execute('SELECT id, email, role FROM `user` WHERE id = ? LIMIT 1', [row.user_id]);
    const user = userRows[0];
    if (!user) return json(res, 400, { message: 'User not found' });

    const newAccess = genAccess({ id: user.id, email: user.email, role: user.role });
    const newRefresh = genRefresh({ id: user.id });
    const newHash = hashTokenRaw(newRefresh);
    const newExpiry = getExpiryDateDays(REFRESH_DAYS);
    await db.execute('INSERT INTO refresh_token (user_id, token_hash, expires_at) VALUES (?, ?, ?)', [user.id, newHash, newExpiry]);

    // reset cookie
    const cookieOpts = {
      httpOnly: true,
      sameSite: 'strict',
      secure: NODE_ENV === 'production',
      path: '/auth/refresh',
      maxAge: REFRESH_DAYS * 24 * 60 * 60 * 1000
    };
    res.cookie('refreshToken', newRefresh, cookieOpts);

    logger.info(`Refresh rotated for user=${user.id}`);
    return json(res, 200, { accessToken: newAccess });

  } catch (err) {
    logger.error('Refresh error: ' + (err.stack || err.message || err));
    return json(res, 500, { message: 'Server error' });
  }
});

/* Logout - revoke refresh token cookie if exists */
app.post('/auth/logout', async (req, res) => {
  try {
    const token = req.cookies.refreshToken;
    if (token) {
      const tokenHash = hashTokenRaw(token);
      await db.execute('UPDATE refresh_token SET revoked=1 WHERE token_hash = ?', [tokenHash]);
    }
    res.clearCookie('refreshToken', { path: '/auth/refresh' });
    return json(res, 200, { message: 'Logged out' });
  } catch (err) {
    logger.error('Logout error: ' + (err.stack || err.message || err));
    return json(res, 500, { message: 'Server error' });
  }
});

/* Get profile - protected */
app.get('/me', authenticate, async (req, res) => {
  const [rows] = await db.execute('SELECT id, username, email, role, created_at FROM `user` WHERE id = ? LIMIT 1', [req.user.id]);
  if (!rows[0]) return json(res, 404, { message: 'User not found' });
  return json(res, 200, { user: rows[0] });
});

/* Change password */
app.post('/me/change-password', authenticate, async (req, res) => {
  const { error, value } = changePwdSchema.validate(req.body);
  if (error) return json(res, 400, { message: error.message });

  const { oldPassword, newPassword } = value;
  const [rows] = await db.execute('SELECT password FROM `user` WHERE id = ? LIMIT 1', [req.user.id]);
  const row = rows[0];
  if (!row) return json(res, 404, { message: 'User not found' });

  const ok = await bcrypt.compare(oldPassword, row.password);
  if (!ok) return json(res, 400, { message: 'Old password incorrect' });

  const newHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
  await db.execute('UPDATE `user` SET password = ? WHERE id = ?', [newHash, req.user.id]);

  // revoke existing refresh tokens (force re-login)
  await db.execute('UPDATE refresh_token SET revoked=1 WHERE user_id = ?', [req.user.id]);

  return json(res, 200, { message: 'Password changed. Please sign in again.' });
});

/* Admin: get all users (no passwords) */
app.get('/admin/users', authenticate, requireRole('admin'), async (req, res) => {
  const [rows] = await db.execute('SELECT id, username, email, role, created_at FROM `user` ORDER BY id DESC');
  return json(res, 200, { users: rows });
});

/* Password reset flow */
// request password reset: create token and store; in prod send email; here we return token for demo
app.post('/auth/request-password-reset', async (req, res) => {
  const { error, value } = requestResetSchema.validate(req.body);
  if (error) return json(res, 400, { message: error.message });

  const { email } = value;
  const [rows] = await db.execute('SELECT id FROM `user` WHERE email = ? LIMIT 1', [email]);
  const user = rows[0];
  if (!user) {
    // don't leak
    return json(res, 200, { message: 'If email exists, a reset link will be sent' });
  }

  const token = uuidv4();
  const expiresAt = getExpiryDateDays(1); // 1 day
  await db.execute('INSERT INTO password_reset (user_id, token, expires_at) VALUES (?, ?, ?)', [user.id, token, expiresAt]);

  // TODO: send link via email in production. For demo we return token (remove this in prod).
  logger.info(`Password reset token created for user=${user.id}`);
  return json(res, 200, { message: 'Password reset token created (send by email in prod)', token });
});

app.post('/auth/reset-password', async (req, res) => {
  const { error, value } = resetSchema.validate(req.body);
  if (error) return json(res, 400, { message: error.message });

  const { token, newPassword } = value;
  const [rows] = await db.execute('SELECT * FROM password_reset WHERE token = ? LIMIT 1', [token]);
  const row = rows[0];
  if (!row) return json(res, 400, { message: 'Invalid token' });
  if (row.used) return json(res, 400, { message: 'Token already used' });
  if (new Date(row.expires_at) < new Date()) return json(res, 400, { message: 'Token expired' });

  const newHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
  await db.execute('UPDATE `user` SET password = ? WHERE id = ?', [newHash, row.user_id]);
  await db.execute('UPDATE password_reset SET used = 1 WHERE id = ?', [row.id]);

  // Revoke existing refresh tokens
  await db.execute('UPDATE refresh_token SET revoked = 1 WHERE user_id = ?', [row.user_id]);

  return json(res, 200, { message: 'Password reset successful. Sign in with new password.' });
});

/* --------- Error handler (Express 5) --------- */
app.use((err, req, res, next) => {
  logger.error(err.stack || err.message || err);
  if (res.headersSent) return next(err);
  return json(res, 500, { message: NODE_ENV === 'production' ? 'Internal server error' : err.message });
});

/* --------- Graceful shutdown --------- */
async function shutdown(signal) {
  try {
    logger.info(`${signal} received. Closing DB pool and exiting.`);
    await db.end();
    process.exit(0);
  } catch (err) {
    logger.error('Error during shutdown: ' + err);
    process.exit(1);
  }
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

/* --------- Start server --------- */
app.listen(PORT, () => {
  logger.info(`Server listening on port ${PORT} (env=${NODE_ENV})`);
});
