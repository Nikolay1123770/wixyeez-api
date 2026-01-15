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
    contentSecurityPolicy: false
}));
app.use(compression());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000
});
app.use('/api/', limiter);

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'wixyeez-super-secret-2024',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
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
const clients = new Map(); // Map для хранения клиентов по user_id

// WebSocket connection handler
wss.on('connection', (ws, req) => {
    console.log('🔌 New WebSocket connection');
    
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
        // Удаляем клиента из всех карт
        for (let [userId, client] of clients) {
            if (client === ws) {
                clients.delete(userId);
                break;
            }
        }
    });
    
    ws.on('error', (error) => {
        console.error('WebSocket error:', error);
    });
});

// Handle WebSocket messages
async function handleWebSocketMessage(ws, data) {
    switch(data.type) {
        case 'register_user':
            // Регистрируем пользователя для уведомлений
            clients.set(data.user_id, ws);
            ws.user_id = data.user_id;
            ws.send(JSON.stringify({
                type: 'registered',
                message: 'User registered for notifications'
            }));
            break;
            
        case 'register_admin':
            ws.isAdmin = true;
            ws.send(JSON.stringify({
                type: 'admin_registered',
                message: 'Admin registered'
            }));
            break;
            
        case 'send_message':
            await handleChatMessage(data);
            break;
            
        case 'get_stats':
            if (ws.isAdmin) {
                await sendStatsToAdmin(ws);
            }
            break;
    }
}

// Handle chat messages
async function handleChatMessage(data) {
    try {
        const { order_id, message, sender_id, sender_type } = data;
        
        // Сохраняем сообщение в БД
        const result = await pool.query(
            `INSERT INTO chat_messages (order_id, sender_id, sender_type, message, created_at)
             VALUES ($1, $2, $3, $4, NOW()) RETURNING *`,
            [order_id, sender_id, sender_type, message]
        );
        
        const savedMessage = result.rows[0];
        
        // Получаем информацию о заказе
        const orderResult = await pool.query('SELECT * FROM orders WHERE id = $1', [order_id]);
        
        if (orderResult.rows.length > 0) {
            const order = orderResult.rows[0];
            
            // Отправляем сообщение получателю
            if (sender_type === 'user') {
                // Отправляем админам
                broadcastToAdmins({
                    type: 'new_message',
                    order_id: order_id,
                    message: savedMessage,
                    customer: order.customer_name
                });
            } else {
                // Отправляем пользователю
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
        console.error('Error handling chat message:', error);
    }
}

// Broadcast to admins
function broadcastToAdmins(data) {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN && client.isAdmin) {
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

// Admin authentication middleware
function requireAdmin(req, res, next) {
    if (req.session.adminId) {
        next();
    } else {
        res.status(401).json({ success: false, error: 'Admin access required' });
    }
}

// ============================================
// API ROUTES
// ============================================

// Create order (обновленный)
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
        
        // Создаем уведомление для пользователя
        await pool.query(
            `INSERT INTO notifications (user_id, type, title, message, data, created_at)
             VALUES ($1, 'order_created', 'Заказ создан', $2, $3, NOW())`,
            [customer_email, `Ваш заказ #${orderId.slice(-8)} успешно создан!`, JSON.stringify(order)]
        );
        
        // Отправляем уведомление пользователю
        sendNotificationToUser(customer_email, {
            title: '🎉 Заказ создан!',
            message: `Заказ #${orderId.slice(-8)} успешно оформлен`,
            order_id: orderId
        });
        
        // Broadcast new order to admins
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

// Get user notifications
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
app.post('/api/user/notifications/mark_read', async (req, res) => {
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

// Get chat messages for order
app.get('/api/chat/:orderId', async (req, res) => {
    try {
        const { orderId } = req.params;
        const { user_email } = req.query;
        
        // Проверяем, что пользователь имеет доступ к этому заказу
        if (!req.session.adminId) {
            const orderResult = await pool.query(
                'SELECT customer_email FROM orders WHERE id = $1',
                [orderId]
            );
            
            if (orderResult.rows.length === 0 || orderResult.rows[0].customer_email !== user_email) {
                return res.status(403).json({ success: false, error: 'Access denied' });
            }
        }
        
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

// Send chat message
app.post('/api/chat/send', async (req, res) => {
    try {
        const { order_id, message, sender_id, sender_type } = req.body;
        
        // Проверяем доступ
        if (sender_type === 'user') {
            const orderResult = await pool.query(
                'SELECT customer_email FROM orders WHERE id = $1',
                [order_id]
            );
            
            if (orderResult.rows.length === 0 || orderResult.rows[0].customer_email !== sender_id) {
                return res.status(403).json({ success: false, error: 'Access denied' });
            }
        } else if (sender_type === 'admin' && !req.session.adminId) {
            return res.status(403).json({ success: false, error: 'Admin access required' });
        }
        
        const result = await pool.query(
            `INSERT INTO chat_messages (order_id, sender_id, sender_type, message, created_at)
             VALUES ($1, $2, $3, $4, NOW()) RETURNING *`,
            [order_id, sender_id, sender_type, message]
        );
        
        // Отправляем через WebSocket
        await handleChatMessage({ order_id, message, sender_id, sender_type });
        
        res.json({ success: true, message: result.rows[0] });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Update order status (обновленный)
app.post('/api/orders/update_status', requireAdmin, async (req, res) => {
    try {
        const { order_id, status } = req.body;
        
        await pool.query(
            'UPDATE orders SET status = $1, updated_at = NOW() WHERE id = $2',
            [status, order_id]
        );
        
        // Получаем информацию о заказе
        const orderResult = await pool.query('SELECT * FROM orders WHERE id = $1', [order_id]);
        const order = orderResult.rows[0];
        
        if (order) {
            // Создаем уведомление для пользователя
            const statusMessages = {
                'processing': 'Ваш заказ обрабатывается',
                'completed': 'Ваш заказ выполнен!',
                'cancelled': 'Ваш заказ отменен'
            };
            
            const message = statusMessages[status] || 'Статус заказа изменен';
            
            await pool.query(
                `INSERT INTO notifications (user_id, type, title, message, data, created_at)
                 VALUES ($1, 'order_status', 'Статус заказа', $2, $3, NOW())`,
                [order.customer_email, message, JSON.stringify({ order_id, status })]
            );
            
            // Отправляем уведомление пользователю
            sendNotificationToUser(order.customer_email, {
                title: '📦 Статус заказа',
                message: message,
                order_id: order_id
            });
        }
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Остальные существующие роуты...
// (весь остальной код остается тем же)

// Initialize database (обновленный)
app.get('/api/init', async (req, res) => {
    try {
        // Создаем все необходимые таблицы
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
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS user_sessions (
                id SERIAL PRIMARY KEY,
                user_id VARCHAR(255) UNIQUE,
                device_token VARCHAR(500),
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Создаем админа по умолчанию
        const adminCheck = await pool.query('SELECT * FROM admins WHERE username = $1', ['admin']);
        
        if (adminCheck.rows.length === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await pool.query('INSERT INTO admins (username, password) VALUES ($1, $2)', ['admin', hashedPassword]);
        }
        
        res.json({ 
            success: true, 
            message: 'Database initialized with chat and notifications!',
            features: [
                'Real-time chat system',
                'Push notifications',
                'Order tracking',
                'User notifications',
                'WebSocket support'
            ]
        });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Start server
server.listen(PORT, () => {
    console.log(`🚀 WIXYEEZ API v3.0 running on port ${PORT}`);
    console.log(`📱 WebSocket server ready for real-time chat & notifications`);
    console.log(`👑 Admin panel: http://localhost:${PORT}/admin`);
});
