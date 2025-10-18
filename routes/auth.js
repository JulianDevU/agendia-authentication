const express = require('express');
const bcrypt = require('bcryptjs');
const { OAuth2Client } = require('google-auth-library');
const { body, validationResult } = require('express-validator');
const { pool } = require('../config/database');
const {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken
} = require('../config/jwt');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

const client = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

// =========================
// VALIDACIONES
// =========================
const loginValidation = [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
];

const changePasswordValidation = [
  body('oldPassword').notEmpty(),
  body('newPassword').isLength({ min: 6 })
];

const registerValidation = [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 }).withMessage('La contraseña debe tener al menos 6 caracteres')
];

// =========================
// REGISTRO NORMAL
// =========================
router.post('/register', registerValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;

  try {
    const existingUser = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'El correo ya está registrado' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (email, password_hash)
       VALUES ($1, $2)
       RETURNING id, email`,
      [email, hashedPassword]
    );

    const user = result.rows[0];
    const accessToken = generateAccessToken(user.id, user.email);
    const refreshToken = generateRefreshToken(user.id);

    await pool.query('UPDATE users SET refresh_token = $1 WHERE id = $2', [refreshToken, user.id]);

    res.status(201).json({
      message: 'Usuario registrado exitosamente',
      user,
      accessToken,
      refreshToken
    });
  } catch (err) {
    console.error('Error en registro:', err);
    res.status(500).json({ error: 'Error al registrar usuario' });
  }
});

// =========================
// GOOGLE AUTH
// =========================

// 1. Redirige al login de Google
router.get('/google', (req, res) => {
  const url = client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: [
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile'
    ],
  });
  res.redirect(url);
});

// 2. Callback de Google (aquí llega el "code")
router.get('/google/callback', async (req, res) => {
  const code = req.query.code;

  try {
    const { tokens } = await client.getToken(code);
    client.setCredentials(tokens);

    // Obtener info del usuario desde Google
    const { data } = await client.request({
      url: 'https://www.googleapis.com/oauth2/v2/userinfo',
    });

    const { email, name, picture } = data;

    // Buscar usuario por email
    let result = await pool.query('SELECT id, email FROM users WHERE email = $1', [email]);
    let user;

    if (result.rows.length === 0) {
      // Crear nuevo usuario Google
      result = await pool.query(
        `INSERT INTO users (email, password_hash, name, picture, provider)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, email, name, picture, provider`,
        [email, null, name, picture, 'google']
      );
      user = result.rows[0];
    } else {
      user = result.rows[0];
      // Actualizar nombre o foto si cambian
      await pool.query(
        `UPDATE users SET name = $1, picture = $2, provider = $3 WHERE id = $4`,
        [name, picture, 'google', user.id]
      );
    }

    // Generar tokens
    const accessToken = generateAccessToken(user.id, user.email);
    const refreshToken = generateRefreshToken(user.id);

    await pool.query('UPDATE users SET refresh_token = $1 WHERE id = $2', [refreshToken, user.id]);

    res.json({
      message: 'Autenticación con Google exitosa',
      user: {
        id: user.id,
        email: user.email,
        name,
        picture,
        provider: 'google'
      },
      accessToken,
      refreshToken
    });
  } catch (err) {
    console.error('❌ Error al autenticar con Google:', err.message);
    res.status(500).json({ error: 'Error al autenticar con Google' });
  }
});

// =========================
// LOGIN NORMAL
// =========================
router.post('/login', loginValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;

  try {
    const result = await pool.query('SELECT id, email, password_hash FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash || '');
    if (!validPassword) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const accessToken = generateAccessToken(user.id, user.email);
    const refreshToken = generateRefreshToken(user.id);

    await pool.query('UPDATE users SET refresh_token = $1 WHERE id = $2', [refreshToken, user.id]);

    res.json({
      accessToken,
      refreshToken,
      user: { id: user.id, email: user.email }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error en login' });
  }
});

// =========================
// CAMBIAR CONTRASEÑA
// =========================
router.post('/change-password', authenticateToken, changePasswordValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { oldPassword, newPassword } = req.body;

  try {
    const result = await pool.query('SELECT id, password_hash FROM users WHERE id = $1', [req.user.userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const user = result.rows[0];

    if (!user.password_hash) {
      return res.status(400).json({ error: 'No se puede cambiar la contraseña para cuentas de Google' });
    }

    const validPassword = await bcrypt.compare(oldPassword, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'La contraseña actual es incorrecta' });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hashedNewPassword, user.id]);

    res.status(200).json({ message: 'Contraseña actualizada exitosamente' });
  } catch (err) {
    console.error('Error al cambiar contraseña:', err);
    res.status(500).json({ error: 'Error al cambiar la contraseña' });
  }
});


// =========================
// REFRESH TOKEN
// =========================
router.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token requerido' });
  }

  try {
    const decoded = verifyRefreshToken(refreshToken);
    const result = await pool.query('SELECT email, refresh_token FROM users WHERE id = $1', [decoded.userId]);

    if (result.rows.length === 0 || result.rows[0].refresh_token !== refreshToken) {
      return res.status(403).json({ error: 'Refresh token inválido' });
    }

    const newAccessToken = generateAccessToken(decoded.userId, result.rows[0].email);
    res.json({ accessToken: newAccessToken });
  } catch (err) {
    res.status(403).json({ error: err.message });
  }
});

// =========================
// LOGOUT
// =========================
router.post('/logout', authenticateToken, async (req, res) => {
  try {
    await pool.query('UPDATE users SET refresh_token = NULL WHERE id = $1', [req.user.userId]);
    res.json({ message: 'Logout exitoso' });
  } catch (err) {
    res.status(500).json({ error: 'Error en logout' });
  }
});

module.exports = router;
