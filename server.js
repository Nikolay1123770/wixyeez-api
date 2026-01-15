const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');
const http = require('http');
const WebSocket = require('ws');
const { v4: uuidv4 } = require('uuid');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

// Security & Performance
app.use(helmet({
    contentSecurityPolicy: false // Для админки
}));
app.use(compression());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 1000 // limit each IP to 1000 requests per windowMs
});
app.use('/api/', limiter);

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'wixyeez-super-secret-2024',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Middleware
app.use(cors({
    origin: true,
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// WebSocket Server
const wss = new WebSocket.Server({ server });
const clients = new Set();

// WebSocket connection handler
wss.on('connection', (ws, req) => {
    console.log('🔌 New WebSocket connection');
    clients.add(ws);
    
    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            handleWebSocketMessage(ws, data);
        } catch (error) {
            console.error('WebSocket message error:', error);
        }
    });
    
    ws.on('close', () => {
        console.log('🔌 WebSocket disconnected');
        clients.delete(ws);
    });
    
    ws.on('error', (error) => {
        console.error('WebSocket error:', error);
        clients.delete(ws);
    });
});

// Handle WebSocket messages
function handleWebSocketMessage(ws, data) {
    switch(data.type) {
        case 'admin_auth':
            ws.isAdmin = true;
            ws.send(JSON.stringify({
                type: 'auth_success',
                message: 'Admin authenticated'
            }));
            break;
            
        case 'get_stats':
            sendStatsToAdmin(ws);
            break;
    }
}

// Broadcast to all admin clients
function broadcastToAdmins(data) {
    clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN && client.isAdmin) {
            client.send(JSON.stringify(data));
        }
    });
}

// Send stats to admin
async function sendStatsToAdmin(ws) {
    try {
        const stats = await getStats();
        ws.send(JSON.stringify({
            type: 'stats_update',
            stats: stats
        }));
    } catch (error) {
        console.error('Error sending stats:', error);
    }
}

// Get statistics
async function getStats() {
    const productsResult = await pool.query('SELECT COUNT(*) FROM products WHERE is_active = true');
    const ordersResult = await pool.query('SELECT COUNT(*), COALESCE(SUM(total_amount), 0) as revenue FROM orders');
    const todayResult = await pool.query(
        "SELECT COUNT(*), COALESCE(SUM(total_amount), 0) as revenue FROM orders WHERE DATE(created_at) = CURRENT_DATE"
    );
    const newOrdersResult = await pool.query("SELECT COUNT(*) FROM orders WHERE status = 'new'");
    const activeUsersResult = await pool.query("SELECT COUNT(DISTINCT customer_email) FROM orders WHERE created_at > NOW() - INTERVAL '1 hour'");
    
    return {
        products: parseInt(productsResult.rows[0].count),
        orders: parseInt(ordersResult.rows[0].count),
        revenue: parseFloat(ordersResult.rows[0].revenue),
        today_orders: parseInt(todayResult.rows[0].count),
        today_revenue: parseFloat(todayResult.rows[0].revenue),
        new_orders: parseInt(newOrdersResult.rows[0].count),
        active_users: parseInt(activeUsersResult.rows[0].count)
    };
}

// ============================================
// ADMIN PANEL ROUTES
// ============================================

app.get('/admin', (req, res) => {
    if (req.session.adminId) {
        res.redirect('/admin/dashboard');
    } else {
        res.sendFile(path.join(__dirname, 'public', 'admin', 'login.html'));
    }
});

app.get('/admin/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin', 'login.html'));
});

app.get('/admin/dashboard', requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin', 'dashboard.html'));
});

app.get('/admin/products', requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin', 'products.html'));
});

app.get('/admin/orders', requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin', 'orders.html'));
});

app.get('/admin/chat', requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin', 'chat.html'));
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
// API ROUTES
// ============================================

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api', (req, res) => {
    res.json({ 
        success: true, 
        message: 'WIXYEEZ API v3.0 - Real-time System',
        version: '3.0.0',
        features: [
            'Real-time admin notifications',
            'WebSocket chat system',
            'Advanced order management',
            'Push notifications',
            'Analytics dashboard'
        ],
        endpoints: {
            products: '/api/products',
            orders: '/api/orders',
            admin: '/admin',
            websocket: 'ws://localhost:' + PORT
        }
    });
});

// Get all products
app.get('/api/get_products.php', async (req, res) => {
    try {
        const category = req.query.category;
        const search = req.query.search;
        
        let query = 'SELECT * FROM products WHERE is_active = true';
        const params = [];
        let paramIndex = 1;
        
        if (category && category !== 'all') {
            query += ` AND category = $${paramIndex}`;
            params.push(category);
            paramIndex++;
        }
        
        if (search) {
            query += ` AND (name ILIKE $${paramIndex} OR description ILIKE $${paramIndex})`;
            params.push(`%${search}%`);
            paramIndex++;
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
        const search = req.query.search;
        
        let query = 'SELECT * FROM products WHERE is_active = true';
        const params = [];
        let paramIndex = 1;
        
        if (category && category !== 'all') {
            query += ` AND category = $${paramIndex}`;
            params.push(category);
            paramIndex++;
        }
        
        if (search) {
            query += ` AND (name ILIKE $${paramIndex} OR description ILIKE $${paramIndex})`;
            params.push(`%${search}%`);
            paramIndex++;
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
        
        const orderId = uuidv4();
        
        const result = await pool.query(
            `INSERT INTO orders (id, customer_name, customer_email, customer_phone, contact_method, 
             items, subtotal, discount_amount, total_amount, promo_code, status, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'new', NOW()) RETURNING *`,
            [orderId, customer_name, customer_email, customer_phone, contact_method, 
             items, subtotal, discount, total, promo_code]
        );
        
        const order = result.rows[0];
        
        // Broadcast new order to admin
        broadcastToAdmins({
            type: 'new_order',
            order: order,
            message: `🆕 Новый заказ от ${customer_name}!`
        });
        
        // Add notification to database
        await pool.query(
            `INSERT INTO notifications (type, title, message, data, created_at)
             VALUES ('new_order', 'Новый заказ', $1, $2, NOW())`,
            [`Заказ #${order.id.slice(-8)} от ${customer_name}`, JSON.stringify(order)]
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

// Get orders (Admin)
app.get('/api/orders', requireAdmin, async (req, res) => {
    try {
        const status = req.query.status || 'all';
        const limit = parseInt(req.query.limit) || 50;
        
        let query = 'SELECT * FROM orders';
        const params = [];
        
        if (status !== 'all') {
            query += ' WHERE status = $1';
            params.push(status);
        }
        
        query += ' ORDER BY created_at DESC LIMIT $' + (params.length + 1);
        params.push(limit);
        
        const result = await pool.query(query, params);
        
        res.json({
            success: true,
            orders: result.rows
        });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Update order status
app.post('/api/orders/update_status', requireAdmin, async (req, res) => {
    try {
        const { order_id, status } = req.body;
        
        await pool.query(
            'UPDATE orders SET status = $1, updated_at = NOW() WHERE id = $2',
            [status, order_id]
        );
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Chat messages
app.post('/api/chat/send', requireAdmin, async (req, res) => {
    try {
        const { order_id, message, recipient_type } = req.body;
        const admin_id = req.session.adminId;
        
        const result = await pool.query(
            `INSERT INTO chat_messages (order_id, admin_id, message, recipient_type, created_at)
             VALUES ($1, $2, $3, $4, NOW()) RETURNING *`,
            [order_id, admin_id, message, recipient_type]
        );
        
        res.json({ success: true, message: result.rows[0] });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get chat messages
app.get('/api/chat/:orderId', requireAdmin, async (req, res) => {
    try {
        const { orderId } = req.params;
        
        const result = await pool.query(
            'SELECT * FROM chat_messages WHERE order_id = $1 ORDER BY created_at ASC',
            [orderId]
        );
        
        res.json({
            success: true,
            messages: result.rows
        });
    } catch (error) {
        console.error('Error:', error);
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

// Login
app.post('/api/login.php', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        console.log('Login attempt:', username);
        
        const result = await pool.query('SELECT * FROM admins WHERE username = $1', [username]);
        
        if (result.rows.length > 0) {
            const admin = result.rows[0];
            const validPassword = await bcrypt.compare(password, admin.password);
            
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

// Stats
app.get('/api/stats.php', async (req, res) => {
    try {
        const stats = await getStats();
        
        const categoryResult = await pool.query(
            'SELECT category, COUNT(*) as count FROM products WHERE is_active = true GROUP BY category'
        );
        
        const topProductResult = await pool.query(`
            SELECT p.name, COUNT(o.id) as order_count 
            FROM products p 
            LEFT JOIN orders o ON o.items LIKE '%' || p.name || '%' 
            WHERE p.is_active = true 
            GROUP BY p.id, p.name 
            ORDER BY order_count DESC 
            LIMIT 1
        `);
        
        stats.categories = categoryResult.rows;
        stats.top_product = topProductResult.rows.length > 0 ? topProductResult.rows[0].name : 'Нет данных';
        
        res.json({
            success: true,
            stats: stats
        });
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get notifications
app.get('/api/notifications', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM notifications ORDER BY created_at DESC LIMIT 50'
        );
        
        res.json({
            success: true,
            notifications: result.rows
        });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Mark notification as read
app.post('/api/notifications/mark_read', requireAdmin, async (req, res) => {
    try {
        const { notification_id } = req.body;
        
        await pool.query(
            'UPDATE notifications SET is_read = true WHERE id = $1',
            [notification_id]
        );
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Initialize database
app.get('/api/init', async (req, res) => {
    try {
        // Create products table
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Create orders table
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
        
        // Create admins table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS admins (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                last_login TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Create chat_messages table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS chat_messages (
                id SERIAL PRIMARY KEY,
                order_id VARCHAR(36) REFERENCES orders(id),
                admin_id INT REFERENCES admins(id),
                message TEXT NOT NULL,
                recipient_type VARCHAR(20) DEFAULT 'customer',
                is_read BOOLEAN DEFAULT false,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Create notifications table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS notifications (
                id SERIAL PRIMARY KEY,
                type VARCHAR(50) NOT NULL,
                title VARCHAR(255) NOT NULL,
                message TEXT NOT NULL,
                data JSONB,
                is_read BOOLEAN DEFAULT false,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Create reviews table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS reviews (
                id SERIAL PRIMARY KEY,
                product_id INT REFERENCES products(id),
                customer_name VARCHAR(255),
                rating INT CHECK (rating >= 1 AND rating <= 5),
                comment TEXT,
                is_approved BOOLEAN DEFAULT false,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Create user_sessions table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS user_sessions (
                id SERIAL PRIMARY KEY,
                session_id VARCHAR(255) UNIQUE,
                user_data JSONB,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Create default admin
        const adminCheck = await pool.query('SELECT * FROM admins WHERE username = $1', ['admin']);
        
        if (adminCheck.rows.length === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await pool.query('INSERT INTO admins (username, password) VALUES ($1, $2)', ['admin', hashedPassword]);
        }
        
        // Create sample products
        const productsCheck = await pool.query('SELECT COUNT(*) FROM products');
        
        if (parseInt(productsCheck.rows[0].count) === 0) {
            const products = [
                ['🔥 VIP Fortnite Account', 'Премиум аккаунт с 200+ скинами, редкими эмотами и эксклюзивными предметами', 'Аккаунты', 4990, 6990, 28, '🎮'],
                ['⚡ Valorant Boost Service', 'Быстрая прокачка рейтинга от Iron до Radiant', 'Услуги', 2990, 3500, 15, '🛡️'],
                ['🚀 CS2 Prime Account', 'Готовый аккаунт с Prime статусом и высоким трастом', 'Аккаунты', 1990, 2500, 20, '🎯'],
                ['💎 Gaming Bundle Pack', 'Полный набор: аккаунт + скины + прокачка', 'Сеты', 7990, 9990, 20, '📦'],
                ['🎯 Персональное сопровождение', 'Индивидуальная поддержка 24/7 на месяц', 'Сопровождение', 3990, 4990, 20, '🤝'],
                ['🏆 Esports Coaching', 'Тренировки с про-игроками', 'Услуги', 5990, 7990, 25, '🏆'],
                ['🔰 Starter Pack', 'Идеальный набор для новичков', 'Сеты', 1990, 2490, 20, '🎁'],
                ['⭐ Premium Support', 'VIP поддержка с приоритетом', 'Сопровождение', 990, 1490, 33, '⭐']
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
            message: 'Database initialized with all tables!',
            features: [
                'Real-time orders system',
                'WebSocket notifications',
                'Chat system',
                'Advanced analytics',
                'Review system'
            ],
            admin_credentials: {
                username: 'admin',
                password: 'admin123',
                url: '/admin'
            }
        });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Start server
server.listen(PORT, () => {
    console.log(`🚀 WIXYEEZ API v3.0 running on port ${PORT}`);
    console.log(`📱 WebSocket server ready for real-time notifications`);
    console.log(`👑 Admin panel: http://localhost:${PORT}/admin`);
});
