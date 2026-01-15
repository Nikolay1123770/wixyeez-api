const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
    origin: true,
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'wixyeez-super-secret-2024',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, 
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: true
    }
}));

// Static files BEFORE routes
app.use(express.static(path.join(__dirname, 'public')));

// Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Admin authentication middleware
function requireAdmin(req, res, next) {
    if (req.session.adminId) {
        next();
    } else {
        res.redirect('/admin/login');
    }
}

// ============================================
// MAIN ROUTES
// ============================================

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================
// ADMIN PANEL ROUTES (ИСПРАВЛЕНО!)
// ============================================

// Admin root - redirect to login or dashboard
app.get('/admin', (req, res) => {
    if (req.session.adminId) {
        res.redirect('/admin/dashboard');
    } else {
        res.redirect('/admin/login');
    }
});

// Admin login page
app.get('/admin/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin', 'login.html'));
});

// Admin dashboard
app.get('/admin/dashboard', requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin', 'dashboard.html'));
});

// Admin products page
app.get('/admin/products', requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin', 'products.html'));
});

// Admin orders page
app.get('/admin/orders', requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin', 'orders.html'));
});

// ============================================
// API ROUTES
// ============================================

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

// Login API
app.post('/api/login.php', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        console.log('Login attempt:', username);
        
        const result = await pool.query('SELECT * FROM admins WHERE username = $1', [username]);
        
        if (result.rows.length > 0) {
            const admin = result.rows[0];
            const validPassword = await bcrypt.compare(password, admin.password);
            
            console.log('Password valid:', validPassword);
            
            if (validPassword) {
                req.session.adminId = admin.id;
                req.session.adminUsername = admin.username;
                
                await pool.query('UPDATE admins SET last_login = NOW() WHERE id = $1', [admin.id]);
                
                res.json({ 
                    success: true, 
                    username: admin.username,
                    message: 'Login successful',
                    redirect: '/admin/dashboard'
                });
            } else {
                res.status(401).json({ success: false, error: 'Invalid password' });
            }
        } else {
            res.status(401).json({ success: false, error: 'User not found' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            res.status(500).json({ success: false, error: 'Logout failed' });
        } else {
            res.json({ success: true, message: 'Logged out successfully' });
        }
    });
});

// Get stats
app.get('/api/stats.php', async (req, res) => {
    try {
        const productsResult = await pool.query('SELECT COUNT(*) FROM products WHERE is_active = true');
        const ordersResult = await pool.query('SELECT COUNT(*), COALESCE(SUM(total_amount), 0) as revenue FROM orders');
        const todayResult = await pool.query(
            "SELECT COUNT(*), COALESCE(SUM(total_amount), 0) as revenue FROM orders WHERE DATE(created_at) = CURRENT_DATE"
        );
        
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
        console.error('Stats error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Add product
app.post('/api/add_product.php', requireAdmin, async (req, res) => {
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

// Update product
app.post('/api/update_product.php', requireAdmin, async (req, res) => {
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

// Delete product
app.get('/api/delete_product.php', requireAdmin, async (req, res) => {
    try {
        const id = req.query.id;
        await pool.query('UPDATE products SET is_active = false WHERE id = $1', [id]);
        res.json({ success: true });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get user orders
app.get('/api/user/orders', async (req, res) => {
    try {
        const { user_email } = req.query;
        
        if (!user_email) {
            return res.status(400).json({ success: false, error: 'User email required' });
        }
        
        const result = await pool.query(
            'SELECT * FROM orders WHERE customer_email = $1 ORDER BY created_at DESC',
            [user_email]
        );
        
        res.json({
            success: true,
            orders: result.rows
        });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Create order
app.post('/api/create_order.php', async (req, res) => {
    try {
        const { 
            customer_name, 
            customer_email, 
            customer_phone, 
            contact_method,
            items,
            subtotal,
            discount,
            total,
            promo_code
        } = req.body;
        
        const { v4: uuidv4 } = require('uuid');
        const orderId = uuidv4();
        
        const result = await pool.query(
            `INSERT INTO orders (id, customer_name, customer_email, customer_phone, contact_method, 
             items, subtotal, discount_amount, total_amount, promo_code, status, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'new', NOW()) RETURNING *`,
            [orderId, customer_name, customer_email, customer_phone, contact_method, 
             items, subtotal, discount, total, promo_code]
        );
        
        res.json({ 
            success: true, 
            order_id: orderId,
            message: 'Заказ успешно создан!'
        });
        
    } catch (error) {
        console.error('Order creation error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Initialize database
app.get('/api/init', async (req, res) => {
    try {
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
                id VARCHAR(36) PRIMARY KEY,
                customer_name VARCHAR(255),
                customer_email VARCHAR(255),
                customer_phone VARCHAR(50),
                contact_method VARCHAR(50),
                items TEXT,
                subtotal DECIMAL(10, 2),
                discount_amount DECIMAL(10, 2) DEFAULT 0,
                total_amount DECIMAL(10, 2),
                promo_code VARCHAR(50),
                status VARCHAR(50) DEFAULT 'new',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS admins (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                last_login TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        const adminCheck = await pool.query('SELECT * FROM admins WHERE username = $1', ['admin']);
        
        if (adminCheck.rows.length === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await pool.query('INSERT INTO admins (username, password) VALUES ($1, $2)', ['admin', hashedPassword]);
        }
        
        const productsCheck = await pool.query('SELECT COUNT(*) FROM products');
        
        if (parseInt(productsCheck.rows[0].count) === 0) {
            const products = [
                ['🔥 VIP Fortnite Account', 'Премиум аккаунт с 200+ скинами', 'Аккаунты', 4990, 6990, 28, '🎮'],
                ['⚡ Valorant Boost', 'Прокачка от Iron до Radiant', 'Услуги', 2990, 3500, 15, '🛡️'],
                ['🚀 CS2 Prime Account', 'Prime + высокий траст', 'Аккаунты', 1990, 2500, 20, '🎯'],
                ['💎 Gaming Bundle', 'Полный набор для геймера', 'Сеты', 7990, 9990, 20, '📦'],
                ['🎯 VIP Support', 'Персональное сопровождение 24/7', 'Сопровождение', 3990, 4990, 20, '🤝']
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

// 404 handler - MUST BE LAST
app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 WIXYEEZ API running on port ${PORT}`);
    console.log(`📱 Main: http://localhost:${PORT}`);
    console.log(`👑 Admin: http://localhost:${PORT}/admin`);
    console.log(`🔧 Init DB: http://localhost:${PORT}/api/init`);
});
