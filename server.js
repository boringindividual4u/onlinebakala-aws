require('dotenv').config();
const { SecretsManagerClient, GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
app.set('trust proxy', 1);
// OWASP A05 - Security Headers via Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "https://picsum.photos", "data:"],
      scriptSrc: ["'self'"]
    }
  }
}));

// CORS - only allow your domain
app.use(cors({
  origin: ['https://bakala.online', 'http://localhost:3000'],
  credentials: true
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser(process.env.COOKIE_SECRET));
app.use(express.static(path.join(__dirname, 'public')));

// Database connection pool
let db;
// OWASP A04 - Rate limiting on auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many attempts. Try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  validate: { xForwardedForHeader: false }
});

app.use('/api/', generalLimiter);

// JWT middleware
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token || 
    (req.headers.authorization && req.headers.authorization.split(' ')[1]);
  
  if (!token) return res.status(401).json({ error: 'Login required' });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// Admin middleware - OWASP A01 Access Control
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// ==================== AUTH ROUTES ====================

// SIGNUP
app.post('/api/auth/signup',
  authLimiter,
  [
    body('email').isEmail().normalizeEmail(),
    body('password')
      .isLength({ min: 8 })
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
      .withMessage('Password must be 8+ chars with uppercase, lowercase and number')
  ],
  async (req, res) => {
    // OWASP A03 - Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
      // Check if email exists
      const [existing] = await db.execute(
        'SELECT id FROM users WHERE email = ?', [email]
      );
      
      if (existing.length > 0) {
        return res.status(409).json({ error: 'Email already registered' });
      }

      // OWASP A02 - Hash password
      const password_hash = await bcrypt.hash(password, 12);

      const [result] = await db.execute(
        'INSERT INTO users (email, password_hash) VALUES (?, ?)',
        [email, password_hash]
      );

      res.status(201).json({ 
        message: 'Account created successfully',
        userId: result.insertId 
      });

    } catch (err) {
      // OWASP A09 - Log error but don't expose details
      console.error('Signup error:', err.message);
      res.status(500).json({ error: 'Registration failed' });
    }
  }
);

// LOGIN
app.post('/api/auth/login',
  authLimiter,
  [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Invalid input' });
    }

    const { email, password } = req.body;

    try {
      // OWASP A03 - Parameterized query
      const [users] = await db.execute(
        'SELECT id, email, password_hash, role, failed_attempts, locked_until FROM users WHERE email = ?',
        [email]
      );

      // OWASP A07 - Generic error message (don't say "email not found")
      if (users.length === 0) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      const user = users[0];

      // OWASP A04 - Check account lockout
      if (user.locked_until && new Date() < new Date(user.locked_until)) {
        return res.status(423).json({ error: 'Account locked. Try again later.' });
      }

      const validPassword = await bcrypt.compare(password, user.password_hash);

      if (!validPassword) {
        // Increment failed attempts
        const attempts = user.failed_attempts + 1;
        const lockUntil = attempts >= 5 
          ? new Date(Date.now() + 15 * 60 * 1000) 
          : null;
        
        await db.execute(
          'UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?',
          [attempts, lockUntil, user.id]
        );

        return res.status(401).json({ error: 'Invalid email or password' });
      }

      // Reset failed attempts on success
      await db.execute(
        'UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?',
        [user.id]
      );

      // Create JWT token
      const token = jwt.sign(
        { userId: user.id, email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );

      // OWASP A02 - Secure httpOnly cookie
      res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000
      });

      res.json({ 
        message: 'Login successful',
        user: { id: user.id, email: user.email, role: user.role }
      });

    } catch (err) {
      console.error('Login error:', err.message);
      res.status(500).json({ error: 'Login failed' });
    }
  }
);

// LOGOUT
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out successfully' });
});

// ==================== PRODUCT ROUTES ====================

// GET all products - public
app.get('/api/products', async (req, res) => {
  try {
    const [products] = await db.execute(
      'SELECT id, name, description, price, image_url, stock FROM products ORDER BY id'
    );
    res.json(products);
  } catch (err) {
    console.error('Products error:', err.message);
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// GET single product - public
app.get('/api/products/:id', async (req, res) => {
  // OWASP A03 - Validate ID is integer
  const id = parseInt(req.params.id);
  if (isNaN(id)) {
    return res.status(400).json({ error: 'Invalid product ID' });
  }

  try {
    const [products] = await db.execute(
      'SELECT id, name, description, price, image_url, stock FROM products WHERE id = ?',
      [id]
    );

    if (products.length === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }

    res.json(products[0]);
  } catch (err) {
    console.error('Product error:', err.message);
    res.status(500).json({ error: 'Failed to fetch product' });
  }
});

// ==================== CART ROUTES ====================

// GET cart
app.get('/api/cart', authenticateToken, async (req, res) => {
  try {
    const [items] = await db.execute(
      `SELECT c.id, c.quantity, p.id as product_id, 
       p.name, p.price, p.image_url
       FROM cart_items c 
       JOIN products p ON c.product_id = p.id 
       WHERE c.user_id = ?`,
      [req.user.userId]
    );
    res.json(items);
  } catch (err) {
    console.error('Cart error:', err.message);
    res.status(500).json({ error: 'Failed to fetch cart' });
  }
});

// ADD to cart
app.post('/api/cart',
  authenticateToken,
  [
    body('product_id').isInt({ min: 1 }),
    body('quantity').isInt({ min: 1, max: 99 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { product_id, quantity } = req.body;

    try {
      // Check product exists and has stock
      const [products] = await db.execute(
        'SELECT id, stock FROM products WHERE id = ?',
        [product_id]
      );

      if (products.length === 0) {
        return res.status(404).json({ error: 'Product not found' });
      }

      if (products[0].stock < quantity) {
        return res.status(400).json({ error: 'Insufficient stock' });
      }

      // Check if already in cart
      const [existing] = await db.execute(
        'SELECT id, quantity FROM cart_items WHERE user_id = ? AND product_id = ?',
        [req.user.userId, product_id]
      );

      if (existing.length > 0) {
        await db.execute(
          'UPDATE cart_items SET quantity = quantity + ? WHERE id = ?',
          [quantity, existing[0].id]
        );
      } else {
        await db.execute(
          'INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?, ?, ?)',
          [req.user.userId, product_id, quantity]
        );
      }

      res.json({ message: 'Added to cart' });
    } catch (err) {
      console.error('Cart add error:', err.message);
      res.status(500).json({ error: 'Failed to add to cart' });
    }
  }
);

// DELETE from cart
app.delete('/api/cart/:id', authenticateToken, async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });

  try {
    // OWASP A01 - Only delete OWN cart items
    await db.execute(
      'DELETE FROM cart_items WHERE id = ? AND user_id = ?',
      [id, req.user.userId]
    );
    res.json({ message: 'Removed from cart' });
  } catch (err) {
    console.error('Cart delete error:', err.message);
    res.status(500).json({ error: 'Failed to remove item' });
  }
});

// ==================== ORDER ROUTES ====================

// PLACE order
app.post('/api/orders', authenticateToken, async (req, res) => {
  const conn = await db.getConnection();
  
  try {
    await conn.beginTransaction();

    // Get cart items
    const [cartItems] = await conn.execute(
      `SELECT c.quantity, p.id, p.price, p.stock, p.name
       FROM cart_items c 
       JOIN products p ON c.product_id = p.id 
       WHERE c.user_id = ?`,
      [req.user.userId]
    );

    if (cartItems.length === 0) {
      await conn.rollback();
      return res.status(400).json({ error: 'Cart is empty' });
    }

    // Calculate total
    const total = cartItems.reduce((sum, item) => 
      sum + (item.price * item.quantity), 0
    );

    // Create order
    const [orderResult] = await conn.execute(
      'INSERT INTO orders (user_id, total) VALUES (?, ?)',
      [req.user.userId, total]
    );

    const orderId = orderResult.insertId;

    // Insert order items and reduce stock
    for (const item of cartItems) {
      if (item.stock < item.quantity) {
        await conn.rollback();
        return res.status(400).json({ 
          error: `Insufficient stock for ${item.name}` 
        });
      }

      await conn.execute(
        'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)',
        [orderId, item.id, item.quantity, item.price]
      );

      await conn.execute(
        'UPDATE products SET stock = stock - ? WHERE id = ?',
        [item.quantity, item.id]
      );
    }

    // Clear cart
    await conn.execute(
      'DELETE FROM cart_items WHERE user_id = ?',
      [req.user.userId]
    );

    await conn.commit();
    res.status(201).json({ message: 'Order placed successfully', orderId });

  } catch (err) {
    await conn.rollback();
    console.error('Order error:', err.message);
    res.status(500).json({ error: 'Failed to place order' });
  } finally {
    conn.release();
  }
});

// GET my orders - OWASP A01 users see only their orders
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const [orders] = await db.execute(
      `SELECT o.id, o.total, o.status, o.created_at,
       COUNT(oi.id) as item_count
       FROM orders o
       LEFT JOIN order_items oi ON o.id = oi.order_id
       WHERE o.user_id = ?
       GROUP BY o.id
       ORDER BY o.created_at DESC`,
      [req.user.userId]
    );
    res.json(orders);
  } catch (err) {
    console.error('Orders error:', err.message);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// ==================== ADMIN ROUTES ====================

// GET all orders - admin only OWASP A01
app.get('/api/admin/orders', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const [orders] = await db.execute(
      `SELECT o.id, o.total, o.status, o.created_at,
       u.email as customer_email
       FROM orders o
       JOIN users u ON o.user_id = u.id
       ORDER BY o.created_at DESC`
    );
    res.json(orders);
  } catch (err) {
    console.error('Admin orders error:', err.message);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// ADD product - admin only
app.post('/api/admin/products',
  authenticateToken,
  requireAdmin,
  [
    body('name').trim().isLength({ min: 1, max: 255 }).escape(),
    body('description').trim().isLength({ max: 1000 }).escape(),
    body('price').isFloat({ min: 0 }),
    body('stock').isInt({ min: 0 }),
    body('image_url').isURL()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, description, price, stock, image_url } = req.body;

    try {
      const [result] = await db.execute(
        'INSERT INTO products (name, description, price, stock, image_url) VALUES (?, ?, ?, ?, ?)',
        [name, description, price, stock, image_url]
      );
      res.status(201).json({ message: 'Product added', id: result.insertId });
    } catch (err) {
      console.error('Add product error:', err.message);
      res.status(500).json({ error: 'Failed to add product' });
    }
  }
);

// UPDATE order status - admin only
app.patch('/api/admin/orders/:id',
  authenticateToken,
  requireAdmin,
  [body('status').isIn(['pending','processing','shipped','delivered'])],
  async (req, res) => {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      await db.execute(
        'UPDATE orders SET status = ? WHERE id = ?',
        [req.body.status, id]
      );
      res.json({ message: 'Order updated' });
    } catch (err) {
      console.error('Update order error:', err.message);
      res.status(500).json({ error: 'Failed to update order' });
    }
  }
);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// OWASP A05 - Don't expose error details
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

const PORT = process.env.PORT || 3000;

async function startServer() {
  try {
    const client = new SecretsManagerClient({ region: 'eu-west-1' });
    const command = new GetSecretValueCommand({ SecretId: 'prod/netflix-app/rds' });
    const response = await client.send(command);
    const creds = JSON.parse(response.SecretString);

    db = mysql.createPool({
      host: process.env.DB_HOST,
      user: creds.username,
      password: creds.password,
      database: process.env.DB_NAME,
      waitForConnections: true,
      connectionLimit: 10,
      connectTimeout: 10000,
      ssl: false
    });

    console.log('DB pool created via Secrets Manager');

    app.listen(PORT, () => {
      console.log(`onlineBakala server running on port ${PORT}`);
      console.log(`Environment: ${process.env.NODE_ENV}`);
    });
  } catch (err) {
    console.error('FATAL - Failed to start server:', err.message);
    process.exit(1);
  }
}

startServer();
