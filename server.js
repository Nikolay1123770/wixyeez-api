const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');
const http = require('http');
const WebSocket = require('ws');
const { v4: uuidv4 } = require('uuid');
const session = require('express-session');

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

// ============================================
// MIDDLEWARE
// ============================================

app.use(cors({
    origin: true,
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Session
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

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// ============================================
// DATABASE
// ============================================

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// ============================================
// WEBSOCKET SERVER
// ============================================

const wss = new WebSocket.Server({ server });
const clients = new Map();
const adminClients = new Set();

wss.on('connection', (ws, req) => {
    console.log('🔌 New WebSocket connection');
    
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });
    
    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);
            await handleWebSocketMessage(ws, data);
        } catch (error) {
            console.error('WebSocket message error:', error);
        }
    });
    
    ws.on('close', () => {
        console.log('🔌 WebSocket disconnected');
        adminClients.delete(ws);
        for (let [id, client] of clients) {
            if (client === ws) {
                clients.delete(id);
                break;
            }
        }
    });
    
    ws.on('error', (error) => {
        console.error('WebSocket error:', error);
    });
});

// Ping interval to keep connections alive
const interval = setInterval(() => {
    wss.clients.forEach((ws) => {
        if (ws.isAlive === false) return ws.terminate();
        ws.isAlive = false;
        ws.ping();
    });
}, 30000);

wss.on('close', () => {
    clearInterval(interval);
});

// Handle WebSocket messages
async function handleWebSocketMessage(ws, data) {
    switch(data.type) {
        case 'register_user':
            clients.set(data.user_id, ws);
            ws.userId = data.user_id;
            ws.send(JSON.stringify({ type: 'registered', message: 'User registered' }));
            console.log('👤 User registered:', data.user_id);
            break;
            
        case 'register_admin':
            adminClients.add(ws);
            ws.isAdmin = true;
            ws.send(JSON.stringify({ type: 'admin_registered', message: 'Admin registered' }));
            console.log('👑 Admin registered');
            break;
            
        case 'chat_message':
            await handleChatMessage(data);
            break;
            
        case 'get_stats':
            if (ws.isAdmin) {
                const stats = await getStats();
                ws.send(JSON.stringify({ type: 'stats_update', stats }));
            }
            break;
    }
}

// Handle chat messages
async function handleChatMessage(data) {
    try {
        const { order_id, message, sender_id, sender_type } = data;
        
        // Save to database
        const result = await pool.query(
            `INSERT INTO chat_messages (order_id, sender_id, sender_type, message, created_at)
             VALUES ($1, $2, $3, $4, NOW()) RETURNING *`,
            [order_id, sender_id, sender_type, message]
        );
        
        const savedMessage = result.rows[0];
        
        // Get order info
        const orderResult = await pool.query('SELECT * FROM orders WHERE id = $1', [order_id]);
        
        if (orderResult.rows.length > 0) {
            const order = orderResult.rows[0];
            
            if (sender_type === 'user') {
                // Send to admins
                broadcastToAdmins({
                    type: 'new_message',
                    order_id: order_id,
                    message: savedMessage,
                    customer_name: order.customer_name,
                    customer_email: order.customer_email
                });
            } else {
                // Send to user
                const userClient = clients.get(order.customer_email);
                if (userClient && userClient.readyState === WebSocket.OPEN) {
                    userClient.send(JSON.stringify({
                        type: 'new_message',
                        order_id: order_id,
                        message: savedMessage
                    }));
                }
            }
        }
    } catch (error) {
        console.error('Chat message error:', error);
    }
}

// Broadcast to all admins
function broadcastToAdmins(data) {
    adminClients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(data));
        }
    });
}

// Send notification to user
function sendNotificationToUser(userId, notification) {
    const client = clients.get(userId);
    if (client && client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({
            type: 'notification',
            ...notification
        }));
    }
}

// Get stats
async function getStats() {
    const productsResult = await pool.query('SELECT COUNT(*) FROM products WHERE is_active = true');
    const ordersResult = await pool.query('SELECT COUNT(*), COALESCE(SUM(total_amount), 0) as revenue FROM orders');
    const todayResult = await pool.query(
        "SELECT COUNT(*), COALESCE(SUM(total_amount), 0) as revenue FROM orders WHERE DATE(created_at) = CURRENT_DATE"
    );
    const newOrdersResult = await pool.query("SELECT COUNT(*) FROM orders WHERE status = 'new'");
    const categoryResult = await pool.query(
        'SELECT category, COUNT(*) as count FROM products WHERE is_active = true GROUP BY category'
    );
    
    return {
        products: parseInt(productsResult.rows[0].count),
        orders: parseInt(ordersResult.rows[0].count),
        revenue: parseFloat(ordersResult.rows[0].revenue || 0),
        today_orders: parseInt(todayResult.rows[0].count),
        today_revenue: parseFloat(todayResult.rows[0].revenue || 0),
        new_orders: parseInt(newOrdersResult.rows[0].count),
        categories: categoryResult.rows
    };
}

// ============================================
// ADMIN MIDDLEWARE
// ============================================

function requireAdmin(req, res, next) {
    if (req.session.adminId) {
        next();
    } else {
        if (req.xhr || req.headers.accept.indexOf('json') > -1) {
            res.status(401).json({ success: false, error: 'Unauthorized' });
        } else {
            res.redirect('/admin/login');
        }
    }
}

// ============================================
// MAIN ROUTES
// ============================================

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api', (req, res) => {
    res.json({ 
        success: true, 
        message: 'WIXYEEZ API v3.0',
        version: '3.0.0',
        endpoints: {
            products: '/api/products',
            orders: '/api/orders',
            admin: '/admin',
            init: '/api/init'
        }
    });
});

// ============================================
// ADMIN ROUTES
// ============================================

app.get('/admin', (req, res) => {
    if (req.session.adminId) {
        res.redirect('/admin/dashboard');
    } else {
        res.redirect('/admin/login');
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

// ============================================
// AUTH API
// ============================================

app.post('/api/login.php', async (req, res) => {
    try {
        const { username, password } = req.body;
        console.log('🔐 Login attempt:', username);
        
        const result = await pool.query('SELECT * FROM admins WHERE username = $1', [username]);
        
        if (result.rows.length > 0) {
            const admin = result.rows[0];
            const validPassword = await bcrypt.compare(password, admin.password);
            
            if (validPassword) {
                req.session.adminId = admin.id;
                req.session.adminUsername = admin.username;
                
                await pool.query('UPDATE admins SET last_login = NOW() WHERE id = $1', [admin.id]);
                
                console.log('✅ Login successful:', username);
                res.json({ 
                    success: true, 
                    username: admin.username,
                    message: 'Login successful',
                    redirect: '/admin/dashboard'
                });
            } else {
                console.log('❌ Invalid password for:', username);
                res.status(401).json({ success: false, error: 'Invalid password' });
            }
        } else {
            console.log('❌ User not found:', username);
            res.status(401).json({ success: false, error: 'User not found' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            res.status(500).json({ success: false, error: 'Logout failed' });
        } else {
            res.json({ success: true, message: 'Logged out' });
        }
    });
});

app.get('/api/auth/check', (req, res) => {
    res.json({
        authenticated: !!req.session.adminId,
        username: req.session.adminUsername || null
    });
});

// ============================================
// PRODUCTS API
// ============================================

app.get('/api/products', async (req, res) => {
    try {
        const { category, search } = req.query;
        
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
        console.error('Products error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/get_products.php', async (req, res) => {
    try {
        const { category } = req.query;
        
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
        console.error('Products error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/products/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('SELECT * FROM products WHERE id = $1', [id]);
        
        if (result.rows.length > 0) {
            res.json({ success: true, product: result.rows[0] });
        } else {
            res.status(404).json({ success: false, error: 'Product not found' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/add_product.php', async (req, res) => {
    try {
        const { name, description, category, price, old_price, discount, emoji, image_url } = req.body;
        
        const emojis = { 'Услуги': '🛡️', 'Сеты': '📦', 'Сопровождение': '🎯', 'Аккаунты': '🎮' };
        const productEmoji = emoji || emojis[category] || '🔥';
        
        const result = await pool.query(
            `INSERT INTO products (name, description, category, price, old_price, discount, emoji, image_url, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW()) RETURNING *`,
            [name, description, category, price, old_price || price, discount || 0, productEmoji, image_url]
        );
        
        console.log('✅ Product added:', name);
        res.json({ success: true, id: result.rows[0].id, product: result.rows[0] });
    } catch (error) {
        console.error('Add product error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/update_product.php', async (req, res) => {
    try {
        const { id, name, description, category, price, old_price, discount, emoji } = req.body;
        
        const emojis = { 'Услуги': '🛡️', 'Сеты': '📦', 'Сопровождение': '🎯', 'Аккаунты': '🎮' };
        const productEmoji = emoji || emojis[category] || '🔥';
        
        await pool.query(
            `UPDATE products SET name=$1, description=$2, category=$3, price=$4, old_price=$5, discount=$6, emoji=$7, updated_at=NOW()
             WHERE id=$8`,
            [name, description, category, price, old_price, discount, productEmoji, id]
        );
        
        console.log('✅ Product updated:', id);
        res.json({ success: true });
    } catch (error) {
        console.error('Update product error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/delete_product.php', async (req, res) => {
    try {
        const { id } = req.query;
        await pool.query('UPDATE products SET is_active = false WHERE id = $1', [id]);
        console.log('🗑️ Product deleted:', id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================
// ORDERS API
// ============================================

app.post('/api/create_order.php', async (req, res) => {
    try {
        const { 
            customer_name, customer_email, customer_phone, contact_method,
            items, subtotal, discount, total, promo_code
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
        console.log('🆕 New order created:', orderId);
        
        // Create notification
        await pool.query(
            `INSERT INTO notifications (user_id, type, title, message, data, created_at)
             VALUES ($1, 'order_created', 'Заказ создан', $2, $3, NOW())`,
            [customer_email, `Заказ #${orderId.slice(-8)} создан!`, JSON.stringify(order)]
        );
        
        // Notify user via WebSocket
        sendNotificationToUser(customer_email, {
            title: '🎉 Заказ создан!',
            message: `Заказ #${orderId.slice(-8)} успешно оформлен`,
            order_id: orderId
        });
        
        // Notify admins via WebSocket
        broadcastToAdmins({
            type: 'new_order',
            order: order,
            message: `🆕 Новый заказ от ${customer_name}!`
        });
        
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

app.get('/api/orders', requireAdmin, async (req, res) => {
    try {
        const { status, limit = 100 } = req.query;
        
        let query = 'SELECT * FROM orders';
        const params = [];
        
        if (status && status !== 'all') {
            query += ' WHERE status = $1';
            params.push(status);
        }
        
        query += ' ORDER BY created_at DESC LIMIT $' + (params.length + 1);
        params.push(limit);
        
        const result = await pool.query(query, params);
        
        res.json({ success: true, orders: result.rows });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/user/orders', async (req, res) => {
    try {
        const { user_email } = req.query;
        
        if (!user_email) {
            return res.status(400).json({ success: false, error: 'Email required' });
        }
        
        const result = await pool.query(
            'SELECT * FROM orders WHERE customer_email = $1 ORDER BY created_at DESC',
            [user_email]
        );
        
        res.json({ success: true, orders: result.rows });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/orders/update_status', requireAdmin, async (req, res) => {
    try {
        const { order_id, status } = req.body;
        
        await pool.query(
            'UPDATE orders SET status = $1, updated_at = NOW() WHERE id = $2',
            [status, order_id]
        );
        
        // Get order info
        const orderResult = await pool.query('SELECT * FROM orders WHERE id = $1', [order_id]);
        const order = orderResult.rows[0];
        
        if (order) {
            const statusMessages = {
                'processing': '⏳ Ваш заказ обрабатывается',
                'completed': '✅ Ваш заказ выполнен!',
                'cancelled': '❌ Ваш заказ отменен'
            };
            
            const message = statusMessages[status] || 'Статус заказа изменен';
            
            // Create notification
            await pool.query(
                `INSERT INTO notifications (user_id, type, title, message, data, created_at)
                 VALUES ($1, 'order_status', 'Статус заказа', $2, $3, NOW())`,
                [order.customer_email, message, JSON.stringify({ order_id, status })]
            );
            
            // Notify user
            sendNotificationToUser(order.customer_email, {
                title: '📦 Статус заказа',
                message: message,
                order_id: order_id
            });
        }
        
        console.log('📦 Order status updated:', order_id, status);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================
// CHAT API
// ============================================

app.get('/api/chat/:orderId', async (req, res) => {
    try {
        const { orderId } = req.params;
        
        const result = await pool.query(
            'SELECT * FROM chat_messages WHERE order_id = $1 ORDER BY created_at ASC',
            [orderId]
        );
        
        res.json({ success: true, messages: result.rows });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/chat/send', async (req, res) => {
    try {
        const { order_id, message, sender_id, sender_type } = req.body;
        
        const result = await pool.query(
            `INSERT INTO chat_messages (order_id, sender_id, sender_type, message, created_at)
             VALUES ($1, $2, $3, $4, NOW()) RETURNING *`,
            [order_id, sender_id, sender_type, message]
        );
        
        // Send via WebSocket
        await handleChatMessage({ order_id, message, sender_id, sender_type });
        
        console.log('💬 Chat message sent:', order_id);
        res.json({ success: true, message: result.rows[0] });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/chat/orders/with-messages', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT DISTINCT o.*, 
                   (SELECT COUNT(*) FROM chat_messages cm WHERE cm.order_id = o.id AND cm.is_read = false AND cm.sender_type = 'user') as unread_count
            FROM orders o
            JOIN chat_messages cm ON o.id = cm.order_id
            ORDER BY o.created_at DESC
        `);
        
        res.json({ success: true, orders: result.rows });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/chat/mark-read', requireAdmin, async (req, res) => {
    try {
        const { order_id } = req.body;
        
        await pool.query(
            "UPDATE chat_messages SET is_read = true WHERE order_id = $1 AND sender_type = 'user'",
            [order_id]
        );
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================
// NOTIFICATIONS API
// ============================================

app.get('/api/user/notifications', async (req, res) => {
    try {
        const { user_id, limit = 50 } = req.query;
        
        if (!user_id) {
            return res.status(400).json({ success: false, error: 'User ID required' });
        }
        
        const result = await pool.query(
            'SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2',
            [user_id, limit]
        );
        
        res.json({ success: true, notifications: result.rows });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/user/notifications/mark_read', async (req, res) => {
    try {
        const { notification_id } = req.body;
        
        await pool.query('UPDATE notifications SET is_read = true WHERE id = $1', [notification_id]);
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/admin/notifications', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT * FROM notifications WHERE type IN ('new_order', 'new_message') ORDER BY created_at DESC LIMIT 100"
        );
        
        res.json({ success: true, notifications: result.rows });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================
// STATS API
// ============================================

app.get('/api/stats.php', async (req, res) => {
    try {
        const stats = await getStats();
        res.json({ success: true, stats });
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================
// PROMO CODES API
// ============================================

app.post('/api/check_promo', async (req, res) => {
    try {
        const { promo_code } = req.body;
        
        const promoCodes = {
            'WIXYEEZ10': { discount: 10, message: 'Скидка 10%!' },
            'METRO20': { discount: 20, message: 'Скидка 20%!' },
            'NEWBIE15': { discount: 15, message: 'Скидка для новичков 15%!' },
            'VIP50': { discount: 50, message: 'VIP скидка 50%!' },
            'WELCOME5': { discount: 5, message: 'Приветственная скидка 5%!' }
        };
        
        const code = promo_code.toUpperCase();
        
        if (promoCodes[code]) {
            res.json({ 
                success: true, 
                valid: true,
                discount: promoCodes[code].discount,
                message: promoCodes[code].message
            });
        } else {
            res.json({ success: true, valid: false, message: 'Неверный промокод' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================
// REVIEWS API
// ============================================

app.get('/api/reviews/:productId', async (req, res) => {
    try {
        const { productId } = req.params;
        
        const result = await pool.query(
            'SELECT * FROM reviews WHERE product_id = $1 AND is_approved = true ORDER BY created_at DESC',
            [productId]
        );
        
        res.json({ success: true, reviews: result.rows });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/reviews/add', async (req, res) => {
    try {
        const { product_id, customer_name, rating, comment } = req.body;
        
        const result = await pool.query(
            `INSERT INTO reviews (product_id, customer_name, rating, comment, is_approved, created_at)
             VALUES ($1, $2, $3, $4, false, NOW()) RETURNING *`,
            [product_id, customer_name, rating, comment]
        );
        
        res.json({ success: true, review: result.rows[0], message: 'Отзыв отправлен на модерацию' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================
// DATABASE INIT
// ============================================

app.get('/api/init', async (req, res) => {
    try {
        // Products table
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
        
        // Orders table
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
        
        // Admins table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS admins (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                last_login TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Chat messages table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS chat_messages (
                id SERIAL PRIMARY KEY,
                order_id VARCHAR(36) NOT NULL,
                sender_id VARCHAR(255) NOT NULL,
                sender_type VARCHAR(20) NOT NULL,
                message TEXT NOT NULL,
                is_read BOOLEAN DEFAULT false,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Notifications table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS notifications (
                id SERIAL PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL,
                type VARCHAR(50) NOT NULL,
                title VARCHAR(255) NOT NULL,
                message TEXT NOT NULL,
                data JSONB,
                is_read BOOLEAN DEFAULT false,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Reviews table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS reviews (
                id SERIAL PRIMARY KEY,
                product_id INT NOT NULL,
                customer_name VARCHAR(255),
                rating INT CHECK (rating >= 1 AND rating <= 5),
                comment TEXT,
                is_approved BOOLEAN DEFAULT false,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Create default admin
        const adminCheck = await pool.query('SELECT * FROM admins WHERE username = $1', ['admin']);
        
        if (adminCheck.rows.length === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await pool.query('INSERT INTO admins (username, password) VALUES ($1, $2)', ['admin', hashedPassword]);
            console.log('✅ Admin created: admin / admin123');
        }
        
        // Create sample products
        const productsCheck = await pool.query('SELECT COUNT(*) FROM products');
        
        if (parseInt(productsCheck.rows[0].count) === 0) {
            const products = [
                ['🔥 VIP Fortnite Account', 'Премиум аккаунт с 200+ скинами, редкими эмотами и Battle Pass', 'Аккаунты', 4990, 6990, 28, '🎮'],
                ['⚡ Valorant Boost Service', 'Быстрая прокачка от Iron до Radiant профессионалами', 'Услуги', 2990, 3500, 15, '🛡️'],
                ['🚀 CS2 Prime Account', 'Готовый аккаунт с Prime статусом и высоким трастом', 'Аккаунты', 1990, 2500, 20, '🎯'],
                ['💎 Gaming Bundle Pack', 'Полный набор: аккаунт + скины + прокачка + бонусы', 'Сеты', 7990, 9990, 20, '📦'],
                ['🎯 Персональное сопровождение', 'Индивидуальная VIP поддержка 24/7 на месяц', 'Сопровождение', 3990, 4990, 20, '🤝'],
                ['🏆 Esports Coaching', 'Тренировки с про-игроками CS2 и Valorant', 'Услуги', 5990, 7990, 25, '🏆'],
                ['🔰 Starter Pack', 'Идеальный набор для новичков со скидкой', 'Сеты', 1990, 2490, 20, '🎁'],
                ['⭐ Premium Support 3 месяца', 'VIP поддержка с приоритетом на квартал', 'Сопровождение', 9990, 14990, 33, '⭐']
            ];
            
            for (const p of products) {
                await pool.query(
                    'INSERT INTO products (name, description, category, price, old_price, discount, emoji) VALUES ($1, $2, $3, $4, $5, $6, $7)',
                    p
                );
            }
            console.log('✅ Sample products created');
        }
        
        res.json({ 
            success: true, 
            message: '🚀 Database initialized successfully!',
            tables: ['products', 'orders', 'admins', 'chat_messages', 'notifications', 'reviews'],
            admin_credentials: { username: 'admin', password: 'admin123' },
            links: {
                main: '/',
                admin: '/admin',
                api: '/api'
            }
        });
        
    } catch (error) {
        console.error('Init error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================
// 404 HANDLER
// ============================================

app.use((req, res) => {
    res.status(404).json({ 
        success: false, 
        error: 'Not Found',
        path: req.path,
        method: req.method
    });
});

// ============================================
// ERROR HANDLER
// ============================================

app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ success: false, error: err.message });
});

// ============================================
// START SERVER
// ============================================

server.listen(PORT, () => {
    console.log('='.repeat(50));
    console.log(`🚀 WIXYEEZ API v3.0 Started!`);
    console.log('='.repeat(50));
    console.log(`📱 Main:      http://localhost:${PORT}`);
    console.log(`👑 Admin:     http://localhost:${PORT}/admin`);
    console.log(`🔧 Init DB:   http://localhost:${PORT}/api/init`);
    console.log(`📦 Products:  http://localhost:${PORT}/api/products`);
    console.log(`🔌 WebSocket: ws://localhost:${PORT}`);
    console.log('='.repeat(50));
});
