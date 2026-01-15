const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'wixyeez-secret-key-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// ============================================
// MIDDLEWARE
// ============================================

// Auth check middleware
const requireAuth = (req, res, next) => {
  if (req.session && req.session.adminId) {
    next();
  } else {
    res.status(401).json({ success: false, error: 'Unauthorized' });
  }
};

// ============================================
// ADMIN PANEL ROUTES
// ============================================

// Serve admin panel
app.get('/admin', (req, res) => {
  if (req.session && req.session.adminId) {
    res.sendFile(path.join(__dirname, 'public', 'admin', 'dashboard.html'));
  } else {
    res.sendFile(path.join(__dirname, 'public', 'admin', 'login.html'));
  }
});

app.get('/admin/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin', 'login.html'));
});

app.get('/admin/dashboard', (req, res) => {
  if (req.session && req.session.adminId) {
    res.sendFile(path.join(__dirname, 'public', 'admin', 'dashboard.html'));
  } else {
    res.redirect('/admin/login');
  }
});

app.get('/admin/products', (req, res) => {
  if (req.session && req.session.adminId) {
    res.sendFile(path.join(__dirname, 'public', 'admin', 'products.html'));
  } else {
    res.redirect('/admin/login');
  }
});

// ============================================
// API ROUTES
// ============================================

// Main page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Test endpoint
app.get('/api', (req, res) => {
  res.json({ 
    success: true, 
    message: 'WIXYEEZ API v2.0',
    endpoints: {
      products: '/api/products',
      admin: '/admin',
      api_docs: '/api/docs'
    }
  });
});

// Get all products
app.get('/api/get_products.php', async (req, res) => {
  try {
    const category = req.query.category;
    
    let query = 'SELECT * FROM products WHERE is_active = true';
    const params = [];
    
    if (category && category !== 'all') {
      query += ' AND category = $1';
      params.push(category);
    }
    
    query += ' ORDER BY created_at DESC';
    
    const result = await pool.query(query, params);
    
    res.json({
      success: true,
      count: result.rows.length,
      products: result.rows
    });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Clean URL for products
app.get('/api/products', async (req, res) => {
  try {
    const category = req.query.category;
    
    let query = 'SELECT * FROM products WHERE is_active = true';
    const params = [];
    
    if (category && category !== 'all') {
      query += ' AND category = $1';
      params.push(category);
    }
    
    query += ' ORDER BY created_at DESC';
    
    const result = await pool.query(query, params);
    
    res.json({
      success: true,
      count: result.rows.length,
      products: result.rows
    });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Add product (protected)
app.post('/api/add_product.php', requireAuth, async (req, res) => {
  try {
    const { name, description, category, price, old_price, discount, emoji, image_url } = req.body;
    
    const emojis = {
      'Услуги': '🛡️',
      'Сеты': '📦',
      'Сопровождение': '🎯'
    };
    
    const productEmoji = emoji || emojis[category] || '🔥';
    
    const result = await pool.query(
      `INSERT INTO products (name, description, category, price, old_price, discount, emoji, image_url)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
      [name, description, category, price, old_price || price, discount || 0, productEmoji, image_url]
    );
    
    res.json({ success: true, id: result.rows[0].id });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Update product (protected)
app.post('/api/update_product.php', requireAuth, async (req, res) => {
  try {
    const { id, name, description, category, price, old_price, discount, emoji } = req.body;
    
    const emojis = {
      'Услуги': '🛡️',
      'Сеты': '📦',
      'Сопровождение': '🎯'
    };
    
    const productEmoji = emoji || emojis[category] || '🔥';
    
    await pool.query(
      `UPDATE products SET name=$1, description=$2, category=$3, price=$4, old_price=$5, discount=$6, emoji=$7
       WHERE id=$8`,
      [name, description, category, price, old_price, discount, productEmoji, id]
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete product (protected)
app.get('/api/delete_product.php', requireAuth, async (req, res) => {
  try {
    const id = req.query.id;
    await pool.query('UPDATE products SET is_active = false WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Login
app.post('/api/login.php', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const result = await pool.query('SELECT * FROM admins WHERE username = $1', [username]);
    
    if (result.rows.length > 0) {
      const admin = result.rows[0];
      const validPassword = await bcrypt.compare(password, admin.password);
      
      if (validPassword) {
        req.session.adminId = admin.id;
        req.session.adminUsername = admin.username;
        
        res.json({ 
          success: true, 
          username: admin.username,
          redirect: '/admin/dashboard'
        });
      } else {
        res.status(401).json({ success: false, error: 'Invalid password' });
      }
    } else {
      res.status(401).json({ success: false, error: 'User not found' });
    }
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      res.status(500).json({ success: false, error: err.message });
    } else {
      res.json({ success: true });
    }
  });
});

// Check auth status
app.get('/api/auth/check', (req, res) => {
  if (req.session && req.session.adminId) {
    res.json({ 
      success: true, 
      authenticated: true,
      username: req.session.adminUsername 
    });
  } else {
    res.json({ 
      success: true, 
      authenticated: false 
    });
  }
});

// Stats (protected)
app.get('/api/stats.php', requireAuth, async (req, res) => {
  try {
    const productsResult = await pool.query('SELECT COUNT(*) FROM products WHERE is_active = true');
    const ordersResult = await pool.query('SELECT COUNT(*), COALESCE(SUM(total_amount), 0) as revenue FROM orders');
    const todayResult = await pool.query(
      "SELECT COUNT(*), COALESCE(SUM(total_amount), 0) as revenue FROM orders WHERE DATE(created_at) = CURRENT_DATE"
    );
    
    // Category breakdown
    const categoryResult = await pool.query(
      'SELECT category, COUNT(*) as count FROM products WHERE is_active = true GROUP BY category'
    );
    
    res.json({
      success: true,
      stats: {
        products: parseInt(productsResult.rows[0].count),
        orders: parseInt(ordersResult.rows[0].count),
        revenue: parseFloat(ordersResult.rows[0].revenue),
        today_orders: parseInt(todayResult.rows[0].count),
        today_revenue: parseFloat(todayResult.rows[0].revenue),
        categories: categoryResult.rows
      }
    });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Initialize database tables
app.get('/api/init', async (req, res) => {
  try {
    // Create tables
    await pool.query(`
      CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        category VARCHAR(50) NOT NULL,
        price DECIMAL(10, 2) NOT NULL,
        old_price DECIMAL(10, 2),
        discount INT DEFAULT 0,
        rating FLOAT DEFAULT 4.5,
        reviews INT DEFAULT 0,
        emoji VARCHAR(10) DEFAULT '🔥',
        image_url VARCHAR(500),
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        customer_name VARCHAR(255),
        customer_contact VARCHAR(255),
        products TEXT,
        total_amount DECIMAL(10, 2),
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admins (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        last_login TIMESTAMP
      )
    `);
    
    // Check if admin exists
    const adminCheck = await pool.query('SELECT * FROM admins WHERE username = $1', ['admin']);
    
    if (adminCheck.rows.length === 0) {
      // Create admin (password: admin123)
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await pool.query('INSERT INTO admins (username, password) VALUES ($1, $2)', ['admin', hashedPassword]);
    }
    
    // Check if products exist
    const productsCheck = await pool.query('SELECT COUNT(*) FROM products');
    
    if (parseInt(productsCheck.rows[0].count) === 0) {
      // Add sample products
      const products = [
        ['Сопровождение на 8 карту 20кк', 'Сопровождений на 8 карту 20кк выдаём фулл 6 с МК ВК', 'Сопровождение', 250, 250, 0, '🎯'],
        ['Буст CS2 Ранга', 'До любого ранга, быстро и безопасно', 'Услуги', 1990, 2500, 20, '🛡️'],
        ['Прокачка Valorant', 'От Iron до Radiant', 'Услуги', 2990, 3500, 15, '🛡️'],
        ['GTA 5 Mega Pack', '500M$, Все машины, Уровень 500+', 'Сеты', 2990, 3990, 25, '📦'],
        ['Сопровождение CS2', 'Полная поддержка 24/7 на месяц', 'Сопровождение', 4990, 6000, 17, '🎯']
      ];
      
      for (const p of products) {
        await pool.query(
          'INSERT INTO products (name, description, category, price, old_price, discount, emoji) VALUES ($1, $2, $3, $4, $5, $6, $7)',
          p
        );
      }
    }
    
    res.json({ 
      success: true, 
      message: 'Database initialized!',
      admin_credentials: {
        username: 'admin',
        password: 'admin123'
      }
    });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 WIXYEEZ API + Admin Panel running on port ${PORT}`);
  console.log(`📊 Admin panel: http://localhost:${PORT}/admin`);
  console.log(`🔌 API endpoint: http://localhost:${PORT}/api`);
});
