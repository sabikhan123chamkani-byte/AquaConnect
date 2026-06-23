const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = 3000;
const MIME_TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'text/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

// Database setup
const dbPath = path.join(__dirname, 'aquaconnect.db');
const db = new DatabaseSync(dbPath);

console.log(`Database initialized at: ${dbPath}`);

// Initialize schema
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT CHECK(role IN ('customer', 'supplier', 'admin')) NOT NULL,
    status TEXT CHECK(status IN ('active', 'suspended')) DEFAULT 'active',
    default_phone TEXT,
    default_address TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS suppliers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE NOT NULL,
    company_name TEXT NOT NULL,
    phone TEXT NOT NULL,
    address TEXT NOT NULL,
    rating REAL DEFAULT 5.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    supplier_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    type TEXT CHECK(type IN ('can', 'mineral_can', 'tanker')) NOT NULL,
    capacity_liters REAL NOT NULL,
    price REAL NOT NULL,
    stock_status TEXT CHECK(stock_status IN ('in_stock', 'out_of_stock')) DEFAULT 'in_stock',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (supplier_id) REFERENCES suppliers(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER NOT NULL,
    supplier_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    total_price REAL NOT NULL,
    address TEXT NOT NULL,
    delivery_date TEXT NOT NULL,
    delivery_time TEXT NOT NULL,
    status TEXT CHECK(status IN ('Pending', 'Accepted', 'Preparing', 'Out for Delivery', 'Delivered', 'Cancelled')) DEFAULT 'Pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES users(id),
    FOREIGN KEY (supplier_id) REFERENCES suppliers(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
  );

  CREATE TABLE IF NOT EXISTS deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER UNIQUE NOT NULL,
    delivery_person_name TEXT,
    delivery_person_phone TEXT,
    estimated_delivery_time TEXT,
    actual_delivery_time TEXT,
    status TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER UNIQUE NOT NULL,
    amount REAL NOT NULL,
    payment_method TEXT NOT NULL,
    payment_status TEXT CHECK(payment_status IN ('Pending', 'Completed', 'Failed')) DEFAULT 'Pending',
    transaction_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    is_read INTEGER CHECK(is_read IN (0, 1)) DEFAULT 0,
    type TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
  CREATE INDEX IF NOT EXISTS idx_orders_customer ON orders(customer_id);
  CREATE INDEX IF NOT EXISTS idx_orders_supplier ON orders(supplier_id);
  CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
  CREATE INDEX IF NOT EXISTS idx_products_supplier ON products(supplier_id);
  CREATE INDEX IF NOT EXISTS idx_notifications_user_read ON notifications(user_id, is_read);
  CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
`);

// Password helper methods
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
}
function generateSalt() {
  return crypto.randomBytes(16).toString('hex');
}
function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

// Seed helper
const checkUsers = db.prepare('SELECT count(*) as count FROM users');
if (checkUsers.all()[0].count === 0) {
  console.log('Seeding initial data into database...');
  
  const insertUser = db.prepare(`
    INSERT INTO users (name, email, password_hash, salt, role, status, default_phone, default_address)
    VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
  `);
  const insertSupplier = db.prepare(`
    INSERT INTO suppliers (user_id, company_name, phone, address, rating)
    VALUES (?, ?, ?, ?, ?)
  `);
  const insertProduct = db.prepare(`
    INSERT INTO products (supplier_id, name, type, capacity_liters, price, stock_status)
    VALUES (?, ?, ?, ?, ?, 'in_stock')
  `);
  const insertOrder = db.prepare(`
    INSERT INTO orders (customer_id, supplier_id, product_id, quantity, total_price, address, delivery_date, delivery_time, status, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const insertPayment = db.prepare(`
    INSERT INTO payments (order_id, amount, payment_method, payment_status, transaction_id)
    VALUES (?, ?, ?, ?, ?)
  `);
  const insertDelivery = db.prepare(`
    INSERT INTO deliveries (order_id, delivery_person_name, delivery_person_phone, estimated_delivery_time, actual_delivery_time, status)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  const insertNotification = db.prepare(`
    INSERT INTO notifications (user_id, message, is_read, type)
    VALUES (?, ?, 0, ?)
  `);

  // 1. Admin
  const adminSalt = generateSalt();
  const adminHash = hashPassword('admin123', adminSalt);
  insertUser.run('AquaConnect Admin', 'admin@aquaconnect.com', adminHash, adminSalt, 'admin', '+92-51-1112223', 'Admin HQ, Sector F-5, Islamabad');

  // 2. Suppliers (Pakistan Retailers)
  const s1Salt = generateSalt();
  const s1Hash = hashPassword('supplier123', s1Salt);
  insertUser.run('Muhammad Bilal', 'supplier1@aquaconnect.com', s1Hash, s1Salt, 'supplier', '+92-300-4567890', 'Plot 42-C, Rahat Commercial Lane 3, DHA Phase 6, Karachi');
  const s1UserId = db.prepare('SELECT last_insert_rowid() as id').all()[0].id;
  insertSupplier.run(s1UserId, 'Pak-Aqua Premium Cans', '+92-300-4567890', 'Plot 42-C, Rahat Commercial Lane 3, DHA Phase 6, Karachi', 4.8);
  const s1Id = db.prepare('SELECT last_insert_rowid() as id').all()[0].id;

  const s2Salt = generateSalt();
  const s2Hash = hashPassword('supplier123', s2Salt);
  insertUser.run('Kamran Khan', 'supplier2@aquaconnect.com', s2Hash, s2Salt, 'supplier', '+92-321-7654321', 'Sector H-9, Near Water Board Office, Islamabad');
  const s2UserId = db.prepare('SELECT last_insert_rowid() as id').all()[0].id;
  insertSupplier.run(s2UserId, 'Indus Water Tanker Service', '+92-321-7654321', 'Sector H-9, Near Water Board Office, Islamabad', 4.9);
  const s2Id = db.prepare('SELECT last_insert_rowid() as id').all()[0].id;

  const s3Salt = generateSalt();
  const s3Hash = hashPassword('supplier123', s3Salt);
  insertUser.run('Zainab Bibi', 'supplier3@aquaconnect.com', s3Hash, s3Salt, 'supplier', '+92-333-9876543', 'Main Boulevard, Gulberg III, Lahore');
  const s3UserId = db.prepare('SELECT last_insert_rowid() as id').all()[0].id;
  insertSupplier.run(s3UserId, 'Lahore Spring Drinking Water', '+92-333-9876543', 'Main Boulevard, Gulberg III, Lahore', 4.7);
  const s3Id = db.prepare('SELECT last_insert_rowid() as id').all()[0].id;

  // 3. Customers (Pakistan Citizens)
  const c1Salt = generateSalt();
  const c1Hash = hashPassword('customer123', c1Salt);
  insertUser.run('Muhammad Ali', 'customer1@aquaconnect.com', c1Hash, c1Salt, 'customer', '+92-315-1112222', 'House 124, Street 12, Sector F-11/1, Islamabad');
  const c1Id = db.prepare('SELECT last_insert_rowid() as id').all()[0].id;

  const c2Salt = generateSalt();
  const c2Hash = hashPassword('customer123', c2Salt);
  insertUser.run('Ayesha Fatima', 'customer2@aquaconnect.com', c2Hash, c2Salt, 'customer', '+92-345-3334444', 'Flat 4B, Al-Mustafa Apartments, Gulshan-e-Iqbal Block 13-D, Karachi');
  const c2Id = db.prepare('SELECT last_insert_rowid() as id').all()[0].id;

  // 4. Products (Prices in PKR)
  insertProduct.run(s1Id, 'Drinking Water Can (20L)', 'can', 20.0, 220.00);
  const p1Id = db.prepare('SELECT last_insert_rowid() as id').all()[0].id;

  insertProduct.run(s1Id, 'Premium Mineral Water Can (20L)', 'mineral_can', 20.0, 350.00);
  const p2Id = db.prepare('SELECT last_insert_rowid() as id').all()[0].id;

  insertProduct.run(s2Id, 'Premium Spring Can (20L)', 'mineral_can', 20.0, 300.00);
  const p3Id = db.prepare('SELECT last_insert_rowid() as id').all()[0].id;

  insertProduct.run(s2Id, 'Small Water Tanker (5000L)', 'tanker', 5000.0, 4500.00);
  const p4Id = db.prepare('SELECT last_insert_rowid() as id').all()[0].id;

  insertProduct.run(s2Id, 'Large Water Tanker (10000L)', 'tanker', 10000.0, 8000.00);
  const p5Id = db.prepare('SELECT last_insert_rowid() as id').all()[0].id;

  insertProduct.run(s3Id, 'Spring Cans Pack of 5 (100L)', 'mineral_can', 100.0, 1400.00);
  const p6Id = db.prepare('SELECT last_insert_rowid() as id').all()[0].id;

  // 5. Orders, Payments, Deliveries
  const dateTwoDaysAgo = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
  insertOrder.run(c1Id, s1Id, p1Id, 5, 1100.00, 'House 124, Street 12, Sector F-11/1, Islamabad', dateTwoDaysAgo, '10:00 AM', 'Delivered', new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString());
  const o1Id = db.prepare('SELECT last_insert_rowid() as id').all()[0].id;
  insertPayment.run(o1Id, 1100.00, 'Cash on Delivery', 'Completed', 'TXN-' + Math.floor(Math.random() * 1000000));
  insertDelivery.run(o1Id, 'Zahid Driver', '+92-312-5551234', '10:30 AM', '10:25 AM', 'Delivered');

  const dateToday = new Date().toISOString().split('T')[0];
  insertOrder.run(c1Id, s1Id, p2Id, 3, 1050.00, 'House 124, Street 12, Sector F-11/1, Islamabad', dateToday, '02:00 PM', 'Preparing', new Date().toISOString());
  const o2Id = db.prepare('SELECT last_insert_rowid() as id').all()[0].id;
  insertPayment.run(o2Id, 1050.00, 'Online Payment', 'Completed', 'TXN-' + Math.floor(Math.random() * 1000000));
  insertDelivery.run(o2Id, 'Zahid Driver', '+92-312-5551234', '02:30 PM', null, 'Preparing');

  insertOrder.run(c2Id, s2Id, p4Id, 1, 4500.00, 'Flat 4B, Al-Mustafa Apartments, Gulshan-e-Iqbal Block 13-D, Karachi', dateToday, '04:00 PM', 'Pending', new Date().toISOString());
  const o3Id = db.prepare('SELECT last_insert_rowid() as id').all()[0].id;
  insertPayment.run(o3Id, 4500.00, 'Cash on Delivery', 'Pending', null);
  insertDelivery.run(o3Id, null, null, null, null, 'Pending');

  // 6. Notifications
  insertNotification.run(c1Id, 'Welcome to AquaConnect Pakistan! Place your first water order today.', 'info');
  insertNotification.run(c1Id, 'Your order #1 has been delivered successfully by Pak-Aqua.', 'success');
  insertNotification.run(s1Id, 'New order #2 received from Muhammad Ali.', 'order');
  insertNotification.run(s2Id, 'New order #3 received from Ayesha Fatima.', 'order');
  
  console.log('Pakistani seed data initialized successfully!');
}

// Session parser helper
function parseCookies(req) {
  const list = {};
  const rc = req.headers.cookie;
  if (rc) {
    rc.split(';').forEach(cookie => {
      const parts = cookie.split('=');
      list[parts.shift().trim()] = decodeURI(parts.join('='));
    });
  }
  return list;
}

// Get user from active session
function getSessionUser(req) {
  const cookies = parseCookies(req);
  const sessionId = cookies.session_id;
  if (!sessionId) return null;
  
  // Clean expired sessions
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now());

  const query = db.prepare(`
    SELECT u.id, u.name, u.email, u.role, u.status, u.default_phone, u.default_address, s.expires_at, sup.id as supplier_id 
    FROM sessions s 
    JOIN users u ON s.user_id = u.id 
    LEFT JOIN suppliers sup ON sup.user_id = u.id
    WHERE s.id = ? AND s.expires_at > ?
  `);
  
  const results = query.all(sessionId, Date.now());
  if (results.length === 0) return null;
  
  const user = results[0];
  if (user.status === 'suspended') return null;
  
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    status: user.status,
    phone: user.default_phone,
    address: user.default_address,
    supplier_id: user.supplier_id
  };
}

// Helper to extract JSON from body
async function getJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (err) {
        reject(err);
      }
    });
  });
}

// Main HTTP request router
async function handleRequest(req, res) {
  // CORS Headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Cookie');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;
  const pathParts = pathname.split('/').filter(Boolean);

  // --- API ROUTING ---
  if (pathParts[0] === 'api') {
    res.setHeader('Content-Type', 'application/json');

    try {
      // 1. AUTHENTICATION & PROFILE ENDPOINTS
      if (pathParts[1] === 'auth') {
        if (pathParts[2] === 'register' && req.method === 'POST') {
          const body = await getJsonBody(req);
          const { name, email, password, role, company_name, phone, address } = body;
          
          if (!name || !email || !password || !role) {
            res.writeHead(400);
            return res.end(JSON.stringify({ error: 'Missing required registration parameters' }));
          }

          if (role !== 'customer' && role !== 'supplier') {
            res.writeHead(400);
            return res.end(JSON.stringify({ error: 'Invalid user role' }));
          }

          if (role === 'supplier' && (!company_name || !phone || !address)) {
            res.writeHead(400);
            return res.end(JSON.stringify({ error: 'Supplier requires business name, phone, and address' }));
          }

          const checkEmail = db.prepare('SELECT id FROM users WHERE email = ?').all(email);
          if (checkEmail.length > 0) {
            res.writeHead(409);
            return res.end(JSON.stringify({ error: 'Email is already registered' }));
          }

          const salt = generateSalt();
          const hash = hashPassword(password, salt);
          
          db.prepare(`
            INSERT INTO users (name, email, password_hash, salt, role, status, default_phone, default_address)
            VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
          `).run(name, email, hash, salt, role, role === 'customer' ? phone : null, role === 'customer' ? address : null);
          
          const newUserId = db.prepare('SELECT last_insert_rowid() as id').all()[0].id;

          let supplierId = null;
          if (role === 'supplier') {
            db.prepare(`
              INSERT INTO suppliers (user_id, company_name, phone, address)
              VALUES (?, ?, ?, ?)
            `).run(newUserId, company_name, phone, address);
            supplierId = db.prepare('SELECT last_insert_rowid() as id').all()[0].id;
          }

          // Automatically log them in by creating a session
          const sessionId = generateSessionId();
          const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
          db.prepare('INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)').run(sessionId, newUserId, expiresAt);

          res.writeHead(200, {
            'Set-Cookie': `session_id=${sessionId}; Path=/; HttpOnly; Max-Age=${7 * 24 * 60 * 60}; SameSite=Lax`,
            'Content-Type': 'application/json'
          });
          return res.end(JSON.stringify({
            success: true,
            user: { id: newUserId, name, email, role, phone, address, supplier_id: supplierId }
          }));
        }

        if (pathParts[2] === 'login' && req.method === 'POST') {
          const body = await getJsonBody(req);
          const { email, password } = body;

          if (!email || !password) {
            res.writeHead(400);
            return res.end(JSON.stringify({ error: 'Email and password are required' }));
          }

          const userRes = db.prepare('SELECT * FROM users WHERE email = ?').all(email);
          if (userRes.length === 0) {
            res.writeHead(401);
            return res.end(JSON.stringify({ error: 'Invalid email or password' }));
          }

          const user = userRes[0];
          if (user.status === 'suspended') {
            res.writeHead(403);
            return res.end(JSON.stringify({ error: 'Your account has been suspended. Please contact admin.' }));
          }

          const calculatedHash = hashPassword(password, user.salt);
          if (calculatedHash !== user.password_hash) {
            res.writeHead(401);
            return res.end(JSON.stringify({ error: 'Invalid email or password' }));
          }

          // Fetch supplier ID if role is supplier
          let supplierId = null;
          if (user.role === 'supplier') {
            const supRes = db.prepare('SELECT id FROM suppliers WHERE user_id = ?').all(user.id);
            if (supRes.length > 0) supplierId = supRes[0].id;
          }

          const sessionId = generateSessionId();
          const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
          db.prepare('INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)').run(sessionId, user.id, expiresAt);

          res.writeHead(200, {
            'Set-Cookie': `session_id=${sessionId}; Path=/; HttpOnly; Max-Age=${7 * 24 * 60 * 60}; SameSite=Lax`,
            'Content-Type': 'application/json'
          });
          return res.end(JSON.stringify({
            success: true,
            user: {
              id: user.id,
              name: user.name,
              email: user.email,
              role: user.role,
              phone: user.default_phone,
              address: user.default_address,
              supplier_id: supplierId
            }
          }));
        }

        if (pathParts[2] === 'logout' && req.method === 'POST') {
          const cookies = parseCookies(req);
          const sessionId = cookies.session_id;
          if (sessionId) {
            db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
          }
          res.writeHead(200, {
            'Set-Cookie': 'session_id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly',
            'Content-Type': 'application/json'
          });
          return res.end(JSON.stringify({ success: true }));
        }

        if (pathParts[2] === 'me' && req.method === 'GET') {
          const user = getSessionUser(req);
          if (!user) {
            res.writeHead(401);
            return res.end(JSON.stringify({ error: 'Unauthorized' }));
          }
          return res.end(JSON.stringify({ user }));
        }

        if (pathParts[2] === 'profile' && req.method === 'PUT') {
          const user = getSessionUser(req);
          if (!user) {
            res.writeHead(401);
            return res.end(JSON.stringify({ error: 'Unauthorized' }));
          }

          const body = await getJsonBody(req);
          const { name, phone, address, company_name, password } = body;

          if (name) {
            db.prepare('UPDATE users SET name = ? WHERE id = ?').run(name, user.id);
          }
          if (password) {
            const salt = generateSalt();
            const hash = hashPassword(password, salt);
            db.prepare('UPDATE users SET password_hash = ?, salt = ? WHERE id = ?').run(hash, salt, user.id);
          }

          if (user.role === 'supplier') {
            db.prepare(`
              UPDATE suppliers 
              SET company_name = COALESCE(?, company_name),
                  phone = COALESCE(?, phone),
                  address = COALESCE(?, address)
              WHERE user_id = ?
            `).run(company_name, phone, address, user.id);
          } else {
            db.prepare(`
              UPDATE users 
              SET default_phone = COALESCE(?, default_phone),
                  default_address = COALESCE(?, default_address)
              WHERE id = ?
            `).run(phone, address, user.id);
          }

          // Return fresh user profile
          const updatedUser = getSessionUser(req);
          res.writeHead(200);
          return res.end(JSON.stringify({ success: true, user: updatedUser }));
        }
      }

      // 2. PRODUCTS ENDPOINTS
      if (pathParts[1] === 'products') {
        const user = getSessionUser(req);
        
        if (req.method === 'GET') {
          // If supplier request, load their own inventory, otherwise load active list
          if (user && user.role === 'supplier') {
            const products = db.prepare(`
              SELECT p.*, s.company_name as supplier_name 
              FROM products p
              JOIN suppliers s ON p.supplier_id = s.id
              WHERE s.user_id = ?
            `).all(user.id);
            res.writeHead(200);
            return res.end(JSON.stringify(products));
          } else {
            const products = db.prepare(`
              SELECT p.*, s.company_name as supplier_name, s.rating as supplier_rating, s.phone as supplier_phone, s.address as supplier_address
              FROM products p
              JOIN suppliers s ON p.supplier_id = s.id
              JOIN users u ON s.user_id = u.id
              WHERE p.stock_status = 'in_stock' AND u.status = 'active'
            `).all();
            res.writeHead(200);
            return res.end(JSON.stringify(products));
          }
        }

        if (req.method === 'POST') {
          if (!user || user.role !== 'supplier') {
            res.writeHead(403);
            return res.end(JSON.stringify({ error: 'Supplier role required' }));
          }

          const body = await getJsonBody(req);
          const { name, type, capacity_liters, price } = body;

          if (!name || !type || !capacity_liters || !price) {
            res.writeHead(400);
            return res.end(JSON.stringify({ error: 'Missing water product details' }));
          }

          db.prepare(`
            INSERT INTO products (supplier_id, name, type, capacity_liters, price)
            VALUES (?, ?, ?, ?, ?)
          `).run(user.supplier_id, name, type, parseFloat(capacity_liters), parseFloat(price));

          res.writeHead(201);
          return res.end(JSON.stringify({ success: true }));
        }

        // PUT /api/products/:id or DELETE /api/products/:id
        if (pathParts.length === 3) {
          const productId = parseInt(pathParts[2]);
          if (!user || user.role !== 'supplier') {
            res.writeHead(403);
            return res.end(JSON.stringify({ error: 'Supplier role required' }));
          }

          if (req.method === 'PUT') {
            const body = await getJsonBody(req);
            const { name, type, capacity_liters, price, stock_status } = body;

            db.prepare(`
              UPDATE products
              SET name = COALESCE(?, name),
                  type = COALESCE(?, type),
                  capacity_liters = COALESCE(?, capacity_liters),
                  price = COALESCE(?, price),
                  stock_status = COALESCE(?, stock_status)
              WHERE id = ? AND supplier_id = ?
            `).run(name, type, capacity_liters ? parseFloat(capacity_liters) : null, price ? parseFloat(price) : null, stock_status, productId, user.supplier_id);

            res.writeHead(200);
            return res.end(JSON.stringify({ success: true }));
          }

          if (req.method === 'DELETE') {
            db.prepare('DELETE FROM products WHERE id = ? AND supplier_id = ?').run(productId, user.supplier_id);
            res.writeHead(200);
            return res.end(JSON.stringify({ success: true }));
          }
        }
      }

      // 3. ORDERS ENDPOINTS
      if (pathParts[1] === 'orders') {
        const user = getSessionUser(req);
        if (!user) {
          res.writeHead(401);
          return res.end(JSON.stringify({ error: 'Unauthorized' }));
        }

        if (req.method === 'GET') {
          let orders;
          if (user.role === 'customer') {
            orders = db.prepare(`
              SELECT o.*, p.name as product_name, p.type as product_type, p.capacity_liters as product_capacity,
                     s.company_name as supplier_name, s.phone as supplier_phone, s.address as supplier_address,
                     del.delivery_person_name, del.delivery_person_phone, del.estimated_delivery_time, del.actual_delivery_time,
                     pay.payment_status, pay.payment_method
              FROM orders o
              JOIN products p ON o.product_id = p.id
              JOIN suppliers s ON o.supplier_id = s.id
              LEFT JOIN deliveries del ON del.order_id = o.id
              LEFT JOIN payments pay ON pay.order_id = o.id
              WHERE o.customer_id = ?
              ORDER BY o.created_at DESC
            `).all(user.id);
          } else if (user.role === 'supplier') {
            orders = db.prepare(`
              SELECT o.*, p.name as product_name, p.type as product_type, p.capacity_liters as product_capacity,
                     u.name as customer_name, u.default_phone as customer_phone,
                     del.delivery_person_name, del.delivery_person_phone, del.estimated_delivery_time, del.actual_delivery_time,
                     pay.payment_status, pay.payment_method
              FROM orders o
              JOIN products p ON o.product_id = p.id
              JOIN users u ON o.customer_id = u.id
              LEFT JOIN deliveries del ON del.order_id = o.id
              LEFT JOIN payments pay ON pay.order_id = o.id
              WHERE o.supplier_id = ?
              ORDER BY o.created_at DESC
            `).all(user.supplier_id);
          } else if (user.role === 'admin') {
            orders = db.prepare(`
              SELECT o.*, p.name as product_name, p.type as product_type, p.capacity_liters as product_capacity,
                     u.name as customer_name, u.default_phone as customer_phone,
                     s.company_name as supplier_name, s.phone as supplier_phone,
                     del.delivery_person_name, del.delivery_person_phone, del.estimated_delivery_time, del.actual_delivery_time,
                     pay.payment_status, pay.payment_method
              FROM orders o
              JOIN products p ON o.product_id = p.id
              JOIN users u ON o.customer_id = u.id
              JOIN suppliers s ON o.supplier_id = s.id
              LEFT JOIN deliveries del ON del.order_id = o.id
              LEFT JOIN payments pay ON pay.order_id = o.id
              ORDER BY o.created_at DESC
            `).all();
          }

          res.writeHead(200);
          return res.end(JSON.stringify(orders));
        }

        if (req.method === 'POST') {
          if (user.role !== 'customer') {
            res.writeHead(403);
            return res.end(JSON.stringify({ error: 'Only customers can place orders' }));
          }

          const body = await getJsonBody(req);
          const { product_id, quantity, address, delivery_date, delivery_time, payment_method } = body;

          if (!product_id || !quantity || !address || !delivery_date || !delivery_time || !payment_method) {
            res.writeHead(400);
            return res.end(JSON.stringify({ error: 'Missing required order details' }));
          }

          const prod = db.prepare('SELECT price, supplier_id FROM products WHERE id = ?').all(product_id);
          if (prod.length === 0) {
            res.writeHead(400);
            return res.end(JSON.stringify({ error: 'Invalid water product selected' }));
          }

          const product = prod[0];
          const total_price = product.price * parseInt(quantity);

          db.prepare(`
            INSERT INTO orders (customer_id, supplier_id, product_id, quantity, total_price, address, delivery_date, delivery_time, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Pending')
          `).run(user.id, product.supplier_id, product_id, parseInt(quantity), total_price, address, delivery_date, delivery_time);

          const orderId = db.prepare('SELECT last_insert_rowid() as id').all()[0].id;

          // Initialize Payment
          db.prepare(`
            INSERT INTO payments (order_id, amount, payment_method, payment_status, transaction_id)
            VALUES (?, ?, ?, ?, ?)
          `).run(orderId, total_price, payment_method, payment_method === 'Online Payment' ? 'Completed' : 'Pending', payment_method === 'Online Payment' ? 'TXN-' + Math.floor(Math.random() * 1000000) : null);

          // Initialize Delivery
          db.prepare(`
            INSERT INTO deliveries (order_id, status)
            VALUES (?, 'Pending')
          `).run(orderId);

          // Alert Supplier
          const supplierUser = db.prepare('SELECT user_id FROM suppliers WHERE id = ?').all(product.supplier_id);
          if (supplierUser.length > 0) {
            db.prepare('INSERT INTO notifications (user_id, message, type) VALUES (?, ?, ?)')
              .run(supplierUser[0].user_id, `New incoming order #${orderId} for ${quantity} cans/tanks.`, 'order');
          }

          res.writeHead(201);
          return res.end(JSON.stringify({ success: true, order_id: orderId }));
        }

        // POST /api/orders/:id/status
        if (pathParts.length === 4 && pathParts[3] === 'status' && req.method === 'POST') {
          const orderId = parseInt(pathParts[2]);
          const body = await getJsonBody(req);
          const { status, delivery_person_name, delivery_person_phone, estimated_delivery_time, actual_delivery_time, payment_status } = body;

          const orderRes = db.prepare('SELECT * FROM orders WHERE id = ?').all(orderId);
          if (orderRes.length === 0) {
            res.writeHead(404);
            return res.end(JSON.stringify({ error: 'Order not found' }));
          }

          const order = orderRes[0];
          if (user.role === 'supplier' && order.supplier_id !== user.supplier_id) {
            res.writeHead(403);
            return res.end(JSON.stringify({ error: 'Forbidden' }));
          }

          if (status) {
            db.prepare('UPDATE orders SET status = ? WHERE id = ?').run(status, orderId);
            db.prepare('UPDATE deliveries SET status = ? WHERE order_id = ?').run(status, orderId);
            
            // Notify customer
            db.prepare('INSERT INTO notifications (user_id, message, type) VALUES (?, ?, ?)')
              .run(order.customer_id, `Your order #${orderId} status has changed to: ${status}.`, 'status_update');

            // Auto complete payment if delivered
            if (status === 'Delivered') {
              db.prepare('UPDATE payments SET payment_status = "Completed" WHERE order_id = ?').run(orderId);
            }
          }

          // Optional delivery agent info
          if (delivery_person_name || delivery_person_phone || estimated_delivery_time || actual_delivery_time) {
            db.prepare(`
              UPDATE deliveries
              SET delivery_person_name = COALESCE(?, delivery_person_name),
                  delivery_person_phone = COALESCE(?, delivery_person_phone),
                  estimated_delivery_time = COALESCE(?, estimated_delivery_time),
                  actual_delivery_time = COALESCE(?, actual_delivery_time),
                  updated_at = CURRENT_TIMESTAMP
              WHERE order_id = ?
            `).run(delivery_person_name, delivery_person_phone, estimated_delivery_time, actual_delivery_time, orderId);
          }

          if (payment_status) {
            db.prepare('UPDATE payments SET payment_status = ? WHERE order_id = ?').run(payment_status, orderId);
          }

          res.writeHead(200);
          return res.end(JSON.stringify({ success: true }));
        }
      }

      // 4. SUPPLIERS DIRECTORY
      if (pathParts[1] === 'suppliers' && req.method === 'GET') {
        const suppliers = db.prepare(`
          SELECT s.*, u.name as owner_name, u.email as owner_email
          FROM suppliers s
          JOIN users u ON s.user_id = u.id
          WHERE u.status = 'active'
        `).all();
        res.writeHead(200);
        return res.end(JSON.stringify(suppliers));
      }

      // 5. NOTIFICATIONS ENDPOINTS
      if (pathParts[1] === 'notifications') {
        const user = getSessionUser(req);
        if (!user) {
          res.writeHead(401);
          return res.end(JSON.stringify({ error: 'Unauthorized' }));
        }

        if (req.method === 'GET') {
          const notifications = db.prepare(`
            SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 30
          `).all(user.id);
          res.writeHead(200);
          return res.end(JSON.stringify(notifications));
        }

        if (pathParts.length === 3 && pathParts[2] === 'read' && req.method === 'POST') {
          db.prepare('UPDATE notifications SET is_read = 1 WHERE user_id = ?').run(user.id);
          res.writeHead(200);
          return res.end(JSON.stringify({ success: true }));
        }
      }

      // 6. ADMIN SECURITY CONTROL ENDPOINTS
      if (pathParts[1] === 'admin') {
        const user = getSessionUser(req);
        if (!user || user.role !== 'admin') {
          res.writeHead(403);
          return res.end(JSON.stringify({ error: 'Admin access required' }));
        }

        if (pathParts[2] === 'users' && req.method === 'GET') {
          const users = db.prepare(`
            SELECT u.id, u.name, u.email, u.role, u.status, u.created_at, u.default_phone, u.default_address,
                   s.company_name, s.phone as supplier_phone, s.address as supplier_address, s.rating as supplier_rating
            FROM users u
            LEFT JOIN suppliers s ON s.user_id = u.id
            WHERE u.role != 'admin'
            ORDER BY u.created_at DESC
          `).all();
          res.writeHead(200);
          return res.end(JSON.stringify(users));
        }

        if (pathParts[2] === 'users' && pathParts[4] === 'status' && req.method === 'POST') {
          const targetUserId = parseInt(pathParts[3]);
          const targetUserRes = db.prepare('SELECT status FROM users WHERE id = ?').all(targetUserId);
          
          if (targetUserRes.length === 0) {
            res.writeHead(404);
            return res.end(JSON.stringify({ error: 'User not found' }));
          }

          const newStatus = targetUserRes[0].status === 'active' ? 'suspended' : 'active';
          db.prepare('UPDATE users SET status = ? WHERE id = ?').run(newStatus, targetUserId);
          
          if (newStatus === 'suspended') {
            db.prepare('DELETE FROM sessions WHERE user_id = ?').run(targetUserId);
          }

          res.writeHead(200);
          return res.end(JSON.stringify({ success: true, status: newStatus }));
        }

        if (pathParts[2] === 'analytics' && req.method === 'GET') {
          const totalUsers = db.prepare("SELECT count(*) as count FROM users WHERE role = 'customer'").all()[0].count;
          const totalSuppliers = db.prepare("SELECT count(*) as count FROM users WHERE role = 'supplier'").all()[0].count;
          const totalOrders = db.prepare("SELECT count(*) as count FROM orders").all()[0].count;
          const totalRevenue = db.prepare("SELECT sum(amount) as sum FROM payments WHERE payment_status = 'Completed'").all()[0].sum || 0;
          
          const orderStats = db.prepare("SELECT status, count(*) as count FROM orders GROUP BY status").all();
          
          const topSuppliers = db.prepare(`
            SELECT s.company_name, count(o.id) as total_orders, sum(o.total_price) as revenue, s.rating
            FROM orders o
            JOIN suppliers s ON o.supplier_id = s.id
            WHERE o.status = 'Delivered'
            GROUP BY s.id
            ORDER BY revenue DESC
            LIMIT 5
          `).all();

          const monthlySales = db.prepare(`
            SELECT strftime('%Y-%m', created_at) as month, sum(total_price) as sales, count(*) as orders
            FROM orders
            GROUP BY month
            ORDER BY month ASC
          `).all();

          res.writeHead(200);
          return res.end(JSON.stringify({
            totalUsers,
            totalSuppliers,
            totalOrders,
            totalRevenue,
            orderStats,
            topSuppliers,
            monthlySales
          }));
        }
      }

      // If api endpoint doesn't match
      res.writeHead(404);
      return res.end(JSON.stringify({ error: 'Endpoint not found' }));

    } catch (e) {
      console.error(e);
      res.writeHead(500);
      return res.end(JSON.stringify({ error: 'Internal Server Error', message: e.message }));
    }
  }

  // --- STATIC FILE SERVING WITH SPA FALLBACK ---
  let filePath = path.join(__dirname, 'public', pathname === '/' ? 'index.html' : pathname);
  filePath = filePath.split('?')[0];

  fs.stat(filePath, (err, stats) => {
    if (err || stats.isDirectory()) {
      // SPA fallback to index.html
      const fallbackPath = path.join(__dirname, 'public', 'index.html');
      fs.readFile(fallbackPath, (err, content) => {
        if (err) {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end('Internal Server Error: Missing frontend index.html');
        } else {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(content);
        }
      });
    } else {
      const ext = path.extname(filePath).toLowerCase();
      const contentType = MIME_TYPES[ext] || 'application/octet-stream';
      fs.readFile(filePath, (err, content) => {
        if (err) {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end('Internal Server Error');
        } else {
          res.writeHead(200, { 'Content-Type': contentType });
          res.end(content);
        }
      });
    }
  });
}

// Start HTTP Server
const server = http.createServer(handleRequest);
server.listen(PORT, () => {
  console.log(`=================================================`);
  console.log(` AquaConnect Production-Ready Server Running!   `);
  console.log(` Address: http://localhost:${PORT}               `);
  console.log(` Database: SQLite built-in node:sqlite           `);
  console.log(` OS Environment: Windows Container               `);
  console.log(`=================================================`);
});
