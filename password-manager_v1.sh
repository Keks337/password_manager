#!/bin/bash

# Password Manager v2.0 - Complete Installation Script
# This script creates a full password manager with admin panel

# 1. System update and dependencies
sudo apt update && sudo apt upgrade -y
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs sqlite3

# 2. Create project directory
mkdir -p /var/www/password-manager
cd /var/www/password-manager

# 3. Create package.json
cat > package.json << 'EOF'
{
  "name": "password-manager-admin",
  "version": "2.0.0",
  "description": "Secure Password Manager with Admin Panel",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "sqlite3": "^5.1.6",
    "bcryptjs": "^2.4.3",
    "express-session": "^1.17.3",
    "helmet": "^7.0.0",
    "express-rate-limit": "^6.10.0",
    "uuid": "^9.0.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}
EOF

# 4. Install dependencies
npm install

# 5. Create the main server file (keeping your existing server.js structure)
cat > server.js << 'EOF'
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Rate limiting - more restrictive for login attempts
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 login attempts per windowMs
  message: { error: 'Слишком много попыток входа. Попробуйте через 15 минут.' }
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

app.use('/api/login', loginLimiter);
app.use(generalLimiter);

// Session configuration with stronger security
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production', // HTTPS in production
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true,
    sameSite: 'strict'
  }
}));

// Database initialization
const db = new sqlite3.Database('./password_manager.db');

// Create tables with better structure
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    failed_attempts INTEGER DEFAULT 0,
    locked_until DATETIME DEFAULT NULL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    site TEXT NOT NULL,
    login TEXT NOT NULL,
    password TEXT NOT NULL,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS admin_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER,
    action TEXT NOT NULL,
    target_user_id INTEGER,
    details TEXT,
    ip_address TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(admin_id) REFERENCES users(id),
    FOREIGN KEY(target_user_id) REFERENCES users(id)
  )`);

  // Create default admin if not exists
  db.get('SELECT * FROM users WHERE is_admin = 1', (err, admin) => {
    if (!admin) {
      const defaultAdminPassword = uuidv4();
      bcrypt.hash(defaultAdminPassword, 12, (err, hashedPassword) => {
        if (!err) {
          db.run('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)', 
            ['admin', hashedPassword, 1], 
            function(err) {
              if (!err) {
                console.log('\n=== ADMIN CREDENTIALS ===');
                console.log('Username: admin');
                console.log('Password:', defaultAdminPassword);
                console.log('Save these credentials securely!');
                console.log('========================\n');
                
                // Save credentials to file
                require('fs').writeFileSync('./ADMIN_CREDENTIALS.txt', 
                  `ADMIN LOGIN CREDENTIALS\n=====================\n\nUsername: admin\nPassword: ${defaultAdminPassword}\n\nCreated: ${new Date().toISOString()}\n\nIMPORTANT: Change this password after first login!\nDelete this file after saving credentials securely.\n`
                );
              }
            }
          );
        }
      });
    }
  });
});

// Enhanced encryption
const algorithm = 'aes-256-gcm';
const secretKey = process.env.ENCRYPTION_KEY || crypto.randomBytes(32);

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipher(algorithm, secretKey);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function decrypt(encryptedText) {
  const decipher = crypto.createDecipher(algorithm, secretKey);
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Middleware
function requireAuth(req, res, next) {
  if (req.session.userId) {
    // Check if user is locked
    db.get('SELECT locked_until FROM users WHERE id = ?', [req.session.userId], (err, user) => {
      if (err) return res.status(500).json({ error: 'Ошибка сервера' });
      if (user && user.locked_until && new Date(user.locked_until) > new Date()) {
        req.session.destroy();
        return res.status(423).json({ error: 'Аккаунт заблокирован' });
      }
      next();
    });
  } else {
    res.status(401).json({ error: 'Необходима авторизация' });
  }
}

function requireAdmin(req, res, next) {
  if (req.session.userId && req.session.isAdmin) {
    next();
  } else {
    res.status(403).json({ error: 'Доступ запрещен' });
  }
}

// Admin logging function
function logAdminAction(req, adminId, action, targetUserId = null, details = null) {
  const ip = req.ip || req.connection.remoteAddress;
  db.run('INSERT INTO admin_logs (admin_id, action, target_user_id, details, ip_address) VALUES (?, ?, ?, ?, ?)', 
    [adminId, action, targetUserId, details, ip]
  );
}

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Authentication routes
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Заполните все поля' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'Пароль должен содержать минимум 8 символов' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 12);
    
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', 
      [username, hashedPassword], 
      function(err) {
        if (err) {
          if (err.code === 'SQLITE_CONSTRAINT') {
            return res.status(400).json({ error: 'Пользователь уже существует' });
          }
          return res.status(500).json({ error: 'Ошибка сервера' });
        }
        res.json({ message: 'Регистрация успешна' });
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Заполните все поля' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Ошибка сервера' });
    }
    
    if (!user) {
      return res.status(400).json({ error: 'Неверные учетные данные' });
    }

    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return res.status(423).json({ error: 'Аккаунт временно заблокирован' });
    }

    try {
      const validPassword = await bcrypt.compare(password, user.password);
      
      if (!validPassword) {
        // Increment failed attempts
        const newFailedAttempts = (user.failed_attempts || 0) + 1;
        let lockedUntil = null;
        
        if (newFailedAttempts >= 5) {
          lockedUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
        }
        
        db.run('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?', 
          [newFailedAttempts, lockedUntil, user.id]);
        
        return res.status(400).json({ 
          error: newFailedAttempts >= 5 ? 'Аккаунт заблокирован на 30 минут' : 'Неверные учетные данные' 
        });
      }

      // Reset failed attempts on successful login
      db.run('UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE id = ?', 
        [user.id]);

      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.isAdmin = user.is_admin === 1;
      
      res.json({ 
        message: 'Вход выполнен успешно', 
        username: user.username,
        isAdmin: user.is_admin === 1
      });
    } catch (error) {
      res.status(500).json({ error: 'Ошибка сервера' });
    }
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Ошибка выхода' });
    }
    res.json({ message: 'Выход выполнен успешно' });
  });
});

// Password management routes
app.get('/api/passwords', requireAuth, (req, res) => {
  db.all('SELECT * FROM passwords WHERE user_id = ? ORDER BY created_at DESC', 
    [req.session.userId], 
    (err, passwords) => {
      if (err) {
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      
      const decryptedPasswords = passwords.map(pwd => ({
        ...pwd,
        password: decrypt(pwd.password)
      }));
      
      res.json(decryptedPasswords);
    }
  );
});

app.post('/api/passwords', requireAuth, (req, res) => {
  const { site, login, password, notes } = req.body;
  
  if (!site || !login || !password) {
    return res.status(400).json({ error: 'Заполните обязательные поля' });
  }

  const encryptedPassword = encrypt(password);
  
  db.run('INSERT INTO passwords (user_id, site, login, password, notes) VALUES (?, ?, ?, ?, ?)', 
    [req.session.userId, site, login, encryptedPassword, notes || ''], 
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      res.json({ message: 'Пароль добавлен успешно', id: this.lastID });
    }
  );
});

app.put('/api/passwords/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const { site, login, password, notes } = req.body;
  
  if (!site || !login || !password) {
    return res.status(400).json({ error: 'Заполните обязательные поля' });
  }

  const encryptedPassword = encrypt(password);
  
  db.run('UPDATE passwords SET site = ?, login = ?, password = ?, notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?', 
    [site, login, encryptedPassword, notes || '', id, req.session.userId], 
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Пароль не найден' });
      }
      res.json({ message: 'Пароль обновлен успешно' });
    }
  );
});

app.delete('/api/passwords/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  
  db.run('DELETE FROM passwords WHERE id = ? AND user_id = ?', 
    [id, req.session.userId], 
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Пароль не найден' });
      }
      res.json({ message: 'Пароль удален успешно' });
    }
  );
});

// Check auth status
app.get('/api/auth/check', (req, res) => {
  if (req.session.userId) {
    res.json({ 
      authenticated: true, 
      username: req.session.username,
      isAdmin: req.session.isAdmin 
    });
  } else {
    res.json({ authenticated: false });
  }
});

// Admin routes
app.get('/api/admin/users', requireAdmin, (req, res) => {
  db.all(`SELECT u.id, u.username, u.is_admin, u.created_at, u.last_login, u.failed_attempts, u.locked_until,
    (SELECT COUNT(*) FROM passwords WHERE user_id = u.id) as password_count
    FROM users u ORDER BY u.created_at DESC`, 
    (err, users) => {
      if (err) {
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      res.json(users);
    }
  );
});

app.get('/api/admin/users/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  
  db.get(`SELECT u.id, u.username, u.is_admin, u.created_at, u.last_login, u.failed_attempts, u.locked_until,
    (SELECT COUNT(*) FROM passwords WHERE user_id = u.id) as password_count
    FROM users u WHERE u.id = ?`, 
    [id], 
    (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      if (!user) {
        return res.status(404).json({ error: 'Пользователь не найден' });
      }
      res.json(user);
    }
  );
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  
  if (id == req.session.userId) {
    return res.status(400).json({ error: 'Нельзя удалить самого себя' });
  }

  db.get('SELECT username FROM users WHERE id = ?', [id], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Ошибка сервера' });
    }
    if (!user) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }

    db.run('DELETE FROM users WHERE id = ?', [id], function(err) {
      if (err) {
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      
      logAdminAction(req, req.session.userId, 'DELETE_USER', id, `Deleted user: ${user.username}`);
      res.json({ message: 'Пользователь удален успешно' });
    });
  });
});

app.put('/api/admin/users/:id/password', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { password } = req.body;
  
  if (!password || password.length < 8) {
    return res.status(400).json({ error: 'Пароль должен содержать минимум 8 символов' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 12);
    
    db.get('SELECT username FROM users WHERE id = ?', [id], (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      if (!user) {
        return res.status(404).json({ error: 'Пользователь не найден' });
      }

      db.run('UPDATE users SET password = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?', 
        [hashedPassword, id], 
        function(err) {
          if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
          }
          
          logAdminAction(req, req.session.userId, 'RESET_PASSWORD', id, `Reset password for user: ${user.username}`);
          res.json({ message: 'Пароль пользователя обновлен успешно' });
        }
      );
    });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.put('/api/admin/users/:id/toggle-admin', requireAdmin, (req, res) => {
  const { id } = req.params;
  
  if (id == req.session.userId) {
    return res.status(400).json({ error: 'Нельзя изменить свои права администратора' });
  }

  db.get('SELECT username, is_admin FROM users WHERE id = ?', [id], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Ошибка сервера' });
    }
    if (!user) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }

    const newAdminStatus = user.is_admin === 1 ? 0 : 1;
    
    db.run('UPDATE users SET is_admin = ? WHERE id = ?', 
      [newAdminStatus, id], 
      function(err) {
        if (err) {
          return res.status(500).json({ error: 'Ошибка сервера' });
        }
        
        const action = newAdminStatus === 1 ? 'GRANT_ADMIN' : 'REVOKE_ADMIN';
        logAdminAction(req, req.session.userId, action, id, `Changed admin status for user: ${user.username}`);
        
        res.json({ 
          message: `Права администратора ${newAdminStatus === 1 ? 'выданы' : 'отозваны'} успешно`,
          isAdmin: newAdminStatus === 1
        });
      }
    );
  });
});

app.put('/api/admin/users/:id/unlock', requireAdmin, (req, res) => {
  const { id } = req.params;
  
  db.get('SELECT username FROM users WHERE id = ?', [id], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Ошибка сервера' });
    }
    if (!user) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }

    db.run('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?', 
      [id], 
      function(err) {
        if (err) {
          return res.status(500).json({ error: 'Ошибка сервера' });
        }
        
        logAdminAction(req, req.session.userId, 'UNLOCK_USER', id, `Unlocked user: ${user.username}`);
        res.json({ message: 'Пользователь разблокирован успешно' });
      }
    );
  });
});

app.get('/api/admin/logs', requireAdmin, (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 50;
  const offset = (page - 1) * limit;
  
  db.all(`SELECT al.*, u.username as admin_username, tu.username as target_username
    FROM admin_logs al
    LEFT JOIN users u ON al.admin_id = u.id
    LEFT JOIN users tu ON al.target_user_id = tu.id
    ORDER BY al.timestamp DESC
    LIMIT ? OFFSET ?`, 
    [limit, offset],
    (err, logs) => {
      if (err) {
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      
      db.get('SELECT COUNT(*) as total FROM admin_logs', (err, count) => {
        if (err) {
          return res.status(500).json({ error: 'Ошибка сервера' });
        }
        
        res.json({
          logs,
          pagination: {
            page,
            limit,
            total: count.total,
            pages: Math.ceil(count.total / limit)
          }
        });
      });
    }
  );
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const stats = {};
  
  Promise.all([
    new Promise((resolve) => {
      db.get('SELECT COUNT(*) as total FROM users', (err, result) => {
        stats.totalUsers = result ? result.total : 0;
        resolve();
      });
    }),
    new Promise((resolve) => {
      db.get('SELECT COUNT(*) as active FROM users WHERE last_login > datetime("now", "-30 days")', (err, result) => {
        stats.activeUsers = result ? result.active : 0;
        resolve();
      });
    }),
    new Promise((resolve) => {
      db.get('SELECT COUNT(*) as total FROM passwords', (err, result) => {
        stats.totalPasswords = result ? result.total : 0;
        resolve();
      });
    }),
    new Promise((resolve) => {
      db.get('SELECT COUNT(*) as today FROM users WHERE date(created_at) = date("now")', (err, result) => {
        stats.newUsersToday = result ? result.today : 0;
        resolve();
      });
    }),
    new Promise((resolve) => {
      db.get('SELECT COUNT(*) as locked FROM users WHERE locked_until > datetime("now")', (err, result) => {
        stats.lockedUsers = result ? result.locked : 0;
        resolve();
      });
    })
  ]).then(() => {
    res.json(stats);
  });
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Внутренняя ошибка сервера' });
});

// Start server
app.listen(PORT, () => {
  console.log(`\n🚀 Password Manager Server запущен на порту ${PORT}`);
  console.log(`📱 Пользовательский интерфейс: http://localhost:${PORT}`);
  console.log(`⚙️  Админ-панель: http://localhost:${PORT}/admin`);
  console.log(`📊 База данных: ./password_manager.db`);
  console.log(`\n⚠️  Проверьте файл ADMIN_CREDENTIALS.txt для данных администратора\n`);
});
EOF

# 6. Create public directory
mkdir -p public

# 7. Create complete main interface (index.html)
cat > public/index.html << 'EOF'
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Manager</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            padding: 40px;
            width: 100%;
            max-width: 1200px;
            transition: all 0.3s ease;
        }

        .auth-container {
            max-width: 400px;
            margin: 0 auto;
        }

        .logo {
            text-align: center;
            margin-bottom: 30px;
        }

        .logo h1 {
            color: #333;
            font-size: 2.5em;
            font-weight: 700;
            margin-bottom: 10px;
        }

        .logo p {
            color: #666;
            font-size: 1.1em;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
        }

        .form-group input, .form-group textarea {
            width: 100%;
            padding: 15px;
            border: 2px solid #e1e5e9;
            border-radius: 10px;
            font-size: 16px;
            transition: all 0.3s ease;
            background: white;
            font-family: inherit;
        }

        .form-group input:focus, .form-group textarea:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        .form-group textarea {
            resize: vertical;
            min-height: 80px;
        }

        .btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-bottom: 15px;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
        }

        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        .btn-secondary {
            background: transparent;
            color: #667eea;
            border: 2px solid #667eea;
			}
			
        .btn-secondary:hover {
            background: rgba(102, 126, 234, 0.1);
        }

        .form-toggle {
            text-align: center;
            margin-top: 20px;
            color: #666;
        }

        .form-toggle a {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
            cursor: pointer;
        }

        .form-toggle a:hover {
            text-decoration: underline;
        }

        .password-container {
            display: none;
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 20px;
            border-bottom: 1px solid #eee;
            margin-bottom: 30px;
        }

        .user-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .welcome {
            font-size: 1.2em;
            font-weight: 500;
        }

        .btn-logout {
            padding: 10px 20px;
            background: #f1f3f9;
            color: #667eea;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .btn-logout:hover {
            background: #e4e8f7;
        }

        .admin-link {
            padding: 10px 20px;
            background: linear-gradient(135deg, #4a8eff 0%, #2d5baf 100%);
            color: white;
            border-radius: 8px;
            font-weight: 600;
            text-decoration: none;
            display: inline-block;
        }

        .password-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }

        .password-card {
            background: white;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
            padding: 20px;
            transition: all 0.3s ease;
            border: 1px solid #eef0f8;
        }

        .password-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1);
        }

        .password-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }

        .site-name {
            font-size: 1.2em;
            font-weight: 600;
            color: #333;
        }

        .password-actions {
            display: flex;
            gap: 10px;
        }

        .action-btn {
            background: none;
            border: none;
            cursor: pointer;
            font-size: 1.1em;
            color: #667eea;
            transition: all 0.3s ease;
        }

        .action-btn:hover {
            color: #4a5fc1;
        }

        .password-field {
            margin-bottom: 12px;
        }

        .field-label {
            font-size: 0.9em;
            color: #666;
            margin-bottom: 4px;
        }

        .field-value {
            font-size: 1.1em;
            font-weight: 500;
            word-break: break-all;
            padding: 8px;
            background: #f9fafc;
            border-radius: 8px;
            border: 1px solid #eee;
        }

        .hidden-password {
            filter: blur(6px);
            transition: filter 0.3s ease;
        }

        .hidden-password:hover {
            filter: blur(0);
        }

        .add-password-btn {
            position: fixed;
            bottom: 30px;
            right: 30px;
            width: 60px;
            height: 60px;
            border-radius: 50%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            font-size: 2em;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.5);
            cursor: pointer;
            transition: all 0.3s ease;
            border: none;
        }

        .add-password-btn:hover {
            transform: scale(1.1) rotate(90deg);
        }

        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.6);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }

        .modal-content {
            background: white;
            border-radius: 20px;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.25);
            width: 90%;
            max-width: 500px;
            padding: 30px;
            animation: modalFade 0.3s ease;
        }

        @keyframes modalFade {
            from { opacity: 0; transform: translateY(-30px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }

        .modal-title {
            font-size: 1.5em;
            font-weight: 600;
            color: #333;
        }

        .close-modal {
            background: none;
            border: none;
            font-size: 1.5em;
            color: #999;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .close-modal:hover {
            color: #333;
        }

        .modal-footer {
            display: flex;
            gap: 15px;
            margin-top: 20px;
        }

        .btn-cancel {
            background: #f1f3f9;
            color: #667eea;
        }

        .btn-cancel:hover {
            background: #e4e8f7;
        }

        .error-message {
            color: #e74c3c;
            text-align: center;
            margin: 15px 0;
            padding: 10px;
            border-radius: 8px;
            background: rgba(231, 76, 60, 0.1);
        }

        .success-message {
            color: #27ae60;
            text-align: center;
            margin: 15px 0;
            padding: 10px;
            border-radius: 8px;
            background: rgba(39, 174, 96, 0.1);
        }

        .password-strength {
            height: 5px;
            background: #eee;
            border-radius: 3px;
            margin-top: 8px;
            overflow: hidden;
        }

        .strength-meter {
            height: 100%;
            width: 0%;
            transition: width 0.3s ease;
        }

        .weak { background: #e74c3c; width: 33%; }
        .medium { background: #f39c12; width: 66%; }
        .strong { background: #27ae60; width: 100%; }

        .toggle-password {
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: #667eea;
            cursor: pointer;
        }

        .input-wrapper {
            position: relative;
        }

        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 25px;
            border-radius: 10px;
            color: white;
            font-weight: 500;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
            z-index: 2000;
            transform: translateX(150%);
            transition: transform 0.4s ease;
        }

        .notification.show {
            transform: translateX(0);
        }

        .notification.success {
            background: #27ae60;
        }

        .notification.error {
            background: #e74c3c;
        }

        @media (max-width: 768px) {
            .container {
                padding: 20px;
            }
            
            .password-grid {
                grid-template-columns: 1fr;
            }
            
            .header {
                flex-direction: column;
                gap: 15px;
                align-items: flex-start;
            }
        }
    </style>
</head>
<body>
    <div class="container auth-container" id="auth-container">
        <div class="logo">
            <h1>🔒 Password Manager</h1>
            <p>Безопасное хранение ваших паролей</p>
        </div>
        
        <div id="login-form">
            <div class="form-group">
                <label for="login-username">Имя пользователя</label>
                <input type="text" id="login-username" placeholder="Введите имя пользователя">
            </div>
            
            <div class="form-group">
                <label for="login-password">Пароль</label>
                <div class="input-wrapper">
                    <input type="password" id="login-password" placeholder="Введите пароль">
                    <button class="toggle-password" id="toggle-login-password">👁️</button>
                </div>
            </div>
            
            <button class="btn" id="login-btn">Войти</button>
            <div class="form-toggle">
                Нет аккаунта? <a id="show-register">Зарегистрироваться</a>
            </div>
            
            <div id="login-error" class="error-message" style="display: none;"></div>
        </div>
        
        <div id="register-form" style="display: none;">
            <div class="form-group">
                <label for="register-username">Имя пользователя</label>
                <input type="text" id="register-username" placeholder="Придумайте имя пользователя">
            </div>
            
            <div class="form-group">
                <label for="register-password">Пароль</label>
                <div class="input-wrapper">
                    <input type="password" id="register-password" placeholder="Придумайте пароль (мин. 8 символов)">
                    <button class="toggle-password" id="toggle-register-password">👁️</button>
                </div>
                <div class="password-strength">
                    <div class="strength-meter" id="password-strength"></div>
                </div>
            </div>
            
            <div class="form-group">
                <label for="register-confirm">Подтверждение пароля</label>
                <div class="input-wrapper">
                    <input type="password" id="register-confirm" placeholder="Повторите пароль">
                    <button class="toggle-password" id="toggle-register-confirm">👁️</button>
                </div>
            </div>
            
            <button class="btn" id="register-btn">Зарегистрироваться</button>
            <div class="form-toggle">
                Уже есть аккаунт? <a id="show-login">Войти</a>
            </div>
            
            <div id="register-error" class="error-message" style="display: none;"></div>
            <div id="register-success" class="success-message" style="display: none;"></div>
        </div>
    </div>
    
    <div class="container password-container" id="password-container">
        <div class="header">
            <div class="logo">
                <h1>🔒 Ваши пароли</h1>
                <p>Все ваши учетные данные в безопасности</p>
            </div>
            
            <div class="user-info">
                <div class="welcome">Добро пожаловать, <span id="current-user"></span>!</div>
                <button class="btn-logout" id="logout-btn">Выйти</button>
                <a href="/admin" class="admin-link" id="admin-link" style="display: none;">Админ-панель</a>
            </div>
        </div>
        
        <div id="password-grid" class="password-grid">
            <!-- Пароли будут загружены сюда -->
        </div>
        
        <button class="add-password-btn" id="add-password-btn">+</button>
    </div>
    
    <div class="modal" id="password-modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title" id="modal-title">Добавить пароль</h3>
                <button class="close-modal" id="close-modal">&times;</button>
            </div>
            
            <div class="form-group">
                <label for="site">Сайт/Сервис</label>
                <input type="text" id="site" placeholder="Например: google.com">
            </div>
            
            <div class="form-group">
                <label for="login">Логин/Email</label>
                <input type="text" id="login" placeholder="Ваш логин для сервиса">
            </div>
            
            <div class="form-group">
                <label for="password">Пароль</label>
                <div class="input-wrapper">
                    <input type="password" id="password" placeholder="Пароль для входа">
                    <button class="toggle-password" id="toggle-password">👁️</button>
                </div>
            </div>
            
            <div class="form-group">
                <label for="notes">Заметки (опционально)</label>
                <textarea id="notes" placeholder="Дополнительная информация"></textarea>
            </div>
            
            <div id="modal-error" class="error-message" style="display: none;"></div>
            
            <div class="modal-footer">
                <button class="btn btn-cancel" id="cancel-modal">Отмена</button>
                <button class="btn" id="save-password">Сохранить</button>
            </div>
        </div>
    </div>
    
    <div id="notification" class="notification"></div>
    
    <script>
        // DOM элементы
        const authContainer = document.getElementById('auth-container');
        const passwordContainer = document.getElementById('password-container');
        const loginForm = document.getElementById('login-form');
        const registerForm = document.getElementById('register-form');
        const passwordGrid = document.getElementById('password-grid');
        const addPasswordBtn = document.getElementById('add-password-btn');
        const passwordModal = document.getElementById('password-modal');
        const currentUserSpan = document.getElementById('current-user');
        const logoutBtn = document.getElementById('logout-btn');
        const adminLink = document.getElementById('admin-link');
        const notification = document.getElementById('notification');
        
        // Переменные состояния
        let currentPasswordId = null;
        
        // Инициализация
        document.addEventListener('DOMContentLoaded', () => {
            checkAuthStatus();
            setupEventListeners();
        });
        
        // Проверка статуса авторизации
        function checkAuthStatus() {
            fetch('/api/auth/check')
                .then(response => response.json())
                .then(data => {
                    if (data.authenticated) {
                        showPasswordManager(data.username, data.isAdmin);
                        loadPasswords();
                    } else {
                        showAuthForm();
                    }
                })
                .catch(error => showNotification('Ошибка сети', 'error'));
        }
        
        // Показать форму авторизации
        function showAuthForm() {
            authContainer.style.display = 'block';
            passwordContainer.style.display = 'none';
        }
        
        // Показать менеджер паролей
        function showPasswordManager(username, isAdmin) {
            authContainer.style.display = 'none';
            passwordContainer.style.display = 'block';
            currentUserSpan.textContent = username;
            adminLink.style.display = isAdmin ? 'block' : 'none';
        }
        
        // Настройка обработчиков событий
        function setupEventListeners() {
            // Переключение форм
            document.getElementById('show-register').addEventListener('click', () => {
                loginForm.style.display = 'none';
                registerForm.style.display = 'block';
            });
            
            document.getElementById('show-login').addEventListener('click', () => {
                registerForm.style.display = 'none';
                loginForm.style.display = 'block';
            });
            
            // Вход
            document.getElementById('login-btn').addEventListener('click', loginUser);
            document.getElementById('login-password').addEventListener('keypress', (e) => {
                if (e.key === 'Enter') loginUser();
            });
            
            // Регистрация
            document.getElementById('register-btn').addEventListener('click', registerUser);
            document.getElementById('register-password').addEventListener('input', checkPasswordStrength);
            
            // Выход
            logoutBtn.addEventListener('click', logoutUser);
            
            // Управление паролями
            addPasswordBtn.addEventListener('click', () => openPasswordModal());
            document.getElementById('close-modal').addEventListener('click', closePasswordModal);
            document.getElementById('cancel-modal').addEventListener('click', closePasswordModal);
            document.getElementById('save-password').addEventListener('click', savePassword);
            
            // Переключение видимости паролей
            setupPasswordToggles();
        }
        
        // Вход пользователя
        function loginUser() {
            const username = document.getElementById('login-username').value;
            const password = document.getElementById('login-password').value;
            
            if (!username || !password) {
                showError('login-error', 'Заполните все поля');
                return;
            }
            
            fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    showError('login-error', data.error);
                } else {
                    showNotification('Вход выполнен успешно', 'success');
                    setTimeout(() => checkAuthStatus(), 1000);
                }
            })
            .catch(error => showError('login-error', 'Ошибка сети'));
        }
        
        // Регистрация пользователя
        function registerUser() {
            const username = document.getElementById('register-username').value;
            const password = document.getElementById('register-password').value;
            const confirm = document.getElementById('register-confirm').value;
            
            if (!username || !password || !confirm) {
                showError('register-error', 'Заполните все поля');
                return;
            }
            
            if (password.length < 8) {
                showError('register-error', 'Пароль должен содержать минимум 8 символов');
                return;
            }
            
            if (password !== confirm) {
                showError('register-error', 'Пароли не совпадают');
                return;
            }
            
            fetch('/api/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    showError('register-error', data.error);
                } else {
                    showSuccess('register-success', 'Регистрация прошла успешно! Теперь вы можете войти.');
                    setTimeout(() => {
                        registerForm.style.display = 'none';
                        loginForm.style.display = 'block';
                        document.getElementById('register-form').reset();
                    }, 2000);
                }
            })
            .catch(error => showError('register-error', 'Ошибка сети'));
        }
        
        // Выход пользователя
        function logoutUser() {
            fetch('/api/logout', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.message) {
                        showNotification('Вы вышли из системы', 'success');
                        setTimeout(() => checkAuthStatus(), 1000);
                    }
                })
                .catch(error => showNotification('Ошибка выхода', 'error'));
        }
        
        // Загрузка паролей
        function loadPasswords() {
            fetch('/api/passwords')
                .then(response => response.json())
                .then(passwords => {
                    renderPasswords(passwords);
                })
                .catch(error => showNotification('Ошибка загрузки паролей', 'error'));
        }
        
        // Отображение паролей
        function renderPasswords(passwords) {
            passwordGrid.innerHTML = '';
            
            if (passwords.length === 0) {
                passwordGrid.innerHTML = `
                    <div class="empty-state">
                        <h3>У вас пока нет сохраненных паролей</h3>
                        <p>Нажмите "+" в правом нижнем углу, чтобы добавить первый пароль</p>
                    </div>
                `;
                return;
            }
            
            passwords.forEach(password => {
                const passwordCard = document.createElement('div');
                passwordCard.className = 'password-card';
                passwordCard.innerHTML = `
                    <div class="password-header">
                        <div class="site-name">${escapeHtml(password.site)}</div>
                        <div class="password-actions">
                            <button class="action-btn edit-password" data-id="${password.id}">✏️</button>
                            <button class="action-btn delete-password" data-id="${password.id}">🗑️</button>
                        </div>
                    </div>
                    <div class="password-field">
                        <div class="field-label">Логин</div>
                        <div class="field-value">${escapeHtml(password.login)}</div>
                    </div>
                    <div class="password-field">
                        <div class="field-label">Пароль</div>
                        <div class="field-value hidden-password">${'*'.repeat(12)}</div>
                    </div>
                    ${password.notes ? `
                    <div class="password-field">
                        <div class="field-label">Заметки</div>
                        <div class="field-value">${escapeHtml(password.notes)}</div>
                    </div>` : ''}
                `;
                
                passwordCard.querySelector('.hidden-password').addEventListener('click', function() {
                    this.textContent = this.textContent.includes('*') 
                        ? escapeHtml(password.password) 
                        : '*'.repeat(12);
                });
                
                passwordCard.querySelector('.edit-password').addEventListener('click', function() {
                    const id = this.getAttribute('data-id');
                    editPassword(id, password);
                });
                
                passwordCard.querySelector('.delete-password').addEventListener('click', function() {
                    const id = this.getAttribute('data-id');
                    deletePassword(id, password.site);
                });
                
                passwordGrid.appendChild(passwordCard);
            });
        }
        
        // Открыть модальное окно для пароля
        function openPasswordModal(password = null) {
            document.getElementById('modal-title').textContent = password 
                ? 'Редактировать пароль' 
                : 'Добавить пароль';
                
            if (password) {
                document.getElementById('site').value = password.site;
                document.getElementById('login').value = password.login;
                document.getElementById('password').value = password.password;
                document.getElementById('notes').value = password.notes || '';
                currentPasswordId = password.id;
            } else {
                document.getElementById('site').value = '';
                document.getElementById('login').value = '';
                document.getElementById('password').value = '';
                document.getElementById('notes').value = '';
                currentPasswordId = null;
            }
            
            document.getElementById('modal-error').style.display = 'none';
            passwordModal.style.display = 'flex';
        }
        
        // Закрыть модальное окно
        function closePasswordModal() {
            passwordModal.style.display = 'none';
        }
        
        // Сохранить пароль
        function savePassword() {
            const site = document.getElementById('site').value;
            const login = document.getElementById('login').value;
            const password = document.getElementById('password').value;
            const notes = document.getElementById('notes').value;
            
            if (!site || !login || !password) {
                showError('modal-error', 'Заполните обязательные поля');
                return;
            }
            
            const url = currentPasswordId 
                ? `/api/passwords/${currentPasswordId}`
                : '/api/passwords';
                
            const method = currentPasswordId ? 'PUT' : 'POST';
            
            fetch(url, {
                method: method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ site, login, password, notes })
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    showError('modal-error', data.error);
                } else {
                    showNotification(
                        currentPasswordId 
                            ? 'Пароль обновлен успешно' 
                            : 'Пароль добавлен успешно',
                        'success'
                    );
                    closePasswordModal();
                    loadPasswords();
                }
            })
            .catch(error => showError('modal-error', 'Ошибка сети'));
        }
        
        // Редактировать пароль
        function editPassword(id, password) {
            openPasswordModal(password);
        }
        
        // Удалить пароль
        function deletePassword(id, site) {
            if (!confirm(`Вы уверены, что хотите удалить пароль для ${site}?`)) return;
            
            fetch(`/api/passwords/${id}`, { method: 'DELETE' })
                .then(response => response.json())
                .then(data => {
                    if (data.message) {
                        showNotification('Пароль удален успешно', 'success');
                        loadPasswords();
                    } else {
                        showNotification('Ошибка удаления пароля', 'error');
                    }
                })
                .catch(error => showNotification('Ошибка сети', 'error'));
        }
        
        // Показать уведомление
        function showNotification(message, type) {
            notification.textContent = message;
            notification.className = `notification ${type} show`;
            
            setTimeout(() => {
                notification.classList.remove('show');
            }, 3000);
        }
        
        // Показать ошибку
        function showError(elementId, message) {
            const errorElement = document.getElementById(elementId);
            errorElement.textContent = message;
            errorElement.style.display = 'block';
        }
        
        // Показать успех
        function showSuccess(elementId, message) {
            const successElement = document.getElementById(elementId);
            successElement.textContent = message;
            successElement.style.display = 'block';
            document.getElementById('register-error').style.display = 'none';
        }
        
        // Проверка силы пароля
        function checkPasswordStrength() {
            const password = document.getElementById('register-password').value;
            const strengthBar = document.getElementById('password-strength');
            
            // Сбросить стили
            strengthBar.className = 'strength-meter';
            
            if (password.length === 0) return;
            
            let strength = 0;
            if (password.length >= 8) strength += 1;
            if (/[A-Z]/.test(password)) strength += 1;
            if (/[0-9]/.test(password)) strength += 1;
            if (/[^A-Za-z0-9]/.test(password)) strength += 1;
            
            if (strength === 1) {
                strengthBar.classList.add('weak');
            } else if (strength === 2) {
                strengthBar.classList.add('medium');
            } else if (strength >= 3) {
                strengthBar.classList.add('strong');
            }
        }
        
        // Настройка переключателей видимости пароля
        function setupPasswordToggles() {
            const toggles = document.querySelectorAll('.toggle-password');
            toggles.forEach(toggle => {
                toggle.addEventListener('click', function() {
                    const input = this.previousElementSibling;
                    const type = input.type === 'password' ? 'text' : 'password';
                    input.type = type;
                    this.textContent = type === 'password' ? '👁️' : '👁️';
                });
            });
        }
        
        // Экранирование HTML
        function escapeHtml(unsafe) {
            return unsafe 
                ? unsafe.toString()
                    .replace(/&/g, "&amp;")
                    .replace(/</g, "&lt;")
                    .replace(/>/g, "&gt;")
                    .replace(/"/g, "&quot;")
                    .replace(/'/g, "&#039;")
                : '';
        }
    </script>
</body>
</html>
EOF

# 8. Create admin panel (admin.html)
cat > public/admin.html << 'EOF'
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel - Password Manager</title>
    <link rel="stylesheet" href="/css/style.css">
    <style>
        .admin-header {
            background: linear-gradient(135deg, #2c3e50 0%, #1a2530 100%);
            color: white;
            padding: 20px;
            border-radius: 15px 15px 0 0;
            margin-bottom: 30px;
        }
        
        .admin-header h1 {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .admin-nav {
            display: flex;
            gap: 15px;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        
        .nav-btn {
            padding: 10px 20px;
            background: rgba(255, 255, 255, 0.1);
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            font-weight: 500;
        }
        
        .nav-btn:hover {
            background: rgba(255, 255, 255, 0.2);
        }
        
        .nav-btn.active {
            background: #4a8eff;
        }
        
        .admin-section {
            display: none;
        }
        
        .admin-section.active {
            display: block;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
            text-align: center;
        }
        
        .stat-value {
            font-size: 2.5em;
            font-weight: 700;
            color: #4a8eff;
            margin: 10px 0;
        }
        
        .stat-label {
            color: #666;
            font-size: 1.1em;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 15px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
        }
        
        th, td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }
        
        th {
            background: #f9fafc;
            font-weight: 600;
            color: #2c3e50;
        }
        
        tr:last-child td {
            border-bottom: none;
        }
        
        tr:hover {
            background: #f9fafc;
        }
        
        .action-btn {
            background: none;
            border: none;
            cursor: pointer;
            font-size: 1.1em;
            margin-right: 10px;
            transition: all 0.3s ease;
        }
        
        .edit-btn { color: #4a8eff; }
        .delete-btn { color: #e74c3c; }
        .unlock-btn { color: #27ae60; }
        
        .action-btn:hover {
            transform: scale(1.2);
        }
        
        .pagination {
            display: flex;
            justify-content: center;
            margin-top: 20px;
            gap: 10px;
        }
        
        .page-btn {
            padding: 8px 15px;
            background: #f1f3f9;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .page-btn.active {
            background: #4a8eff;
            color: white;
        }
        
        .admin-modal {
            background: rgba(0, 0, 0, 0.7);
        }
        
        .admin-modal-content {
            max-width: 500px;
        }
        
        .modal-actions {
            display: flex;
            gap: 15px;
        }
        
        .password-reset-container {
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="admin-header">
            <h1>⚙️ Административная панель</h1>
            <div class="user-info">
                <div class="welcome">Администратор: <span id="admin-username"></span></div>
                <button class="btn-logout" id="admin-logout">Выйти</button>
            </div>
            
            <div class="admin-nav">
                <button class="nav-btn active" data-target="dashboard">Дашборд</button>
                <button class="nav-btn" data-target="users">Пользователи</button>
                <button class="nav-btn" data-target="logs">Логи действий</button>
            </div>
        </div>
        
        <!-- Dashboard Section -->
        <div id="dashboard" class="admin-section active">
            <h2>📊 Общая статистика</h2>
            <div class="stats-grid" id="stats-grid">
                <!-- Статистика будет загружена сюда -->
            </div>
            
            <h2>👥 Последние пользователи</h2>
            <div class="table-responsive">
                <table id="recent-users">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Имя пользователя</th>
                            <th>Дата регистрации</th>
                            <th>Последний вход</th>
                            <th>Паролей</th>
                            <th>Статус</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Данные будут загружены -->
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Users Section -->
        <div id="users" class="admin-section">
            <h2>👥 Управление пользователями</h2>
            <div class="table-responsive">
                <table id="users-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Имя пользователя</th>
                            <th>Администратор</th>
                            <th>Дата регистрации</th>
                            <th>Паролей</th>
                            <th>Статус</th>
                            <th>Действия</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Данные будут загружены -->
                    </tbody>
                </table>
            </div>
            
            <div class="pagination" id="users-pagination">
                <!-- Пагинация будет сгенерирована -->
            </div>
        </div>
        
        <!-- Logs Section -->
        <div id="logs" class="admin-section">
            <h2>📝 Логи административных действий</h2>
            <div class="table-responsive">
                <table id="logs-table">
                    <thead>
                        <tr>
                            <th>Дата</th>
                            <th>Администратор</th>
                            <th>Действие</th>
                            <th>Цель</th>
                            <th>Детали</th>
                            <th>IP</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Данные будут загружены -->
                    </tbody>
                </table>
            </div>
            
            <div class="pagination" id="logs-pagination">
                <!-- Пагинация будет сгенерирована -->
            </div>
        </div>
    </div>
    
    <!-- User Modal -->
    <div class="modal admin-modal" id="user-modal">
        <div class="modal-content admin-modal-content">
            <div class="modal-header">
                <h3 class="modal-title" id="user-modal-title">Детали пользователя</h3>
                <button class="close-modal" id="close-user-modal">&times;</button>
            </div>
            
            <div id="user-details">
                <!-- Детали пользователя будут загружены -->
            </div>
            
            <div class="password-reset-container">
                <h4>Сброс пароля</h4>
                <div class="form-group">
                    <label for="new-password">Новый пароль</label>
                    <input type="password" id="new-password" placeholder="Введите новый пароль">
                </div>
                
                <div id="password-reset-error" class="error-message" style="display: none;"></div>
                
                <div class="modal-footer">
                    <button class="btn btn-cancel" id="cancel-reset">Отмена</button>
                    <button class="btn" id="reset-password-btn">Сбросить пароль</button>
                </div>
            </div>
        </div>
    </div>
    
    <div id="admin-notification" class="notification"></div>
    
    <script src="/js/admin.js"></script>
</body>
</html>
EOF

# 9. Create CSS file
mkdir -p public/css
cat > public/css/style.css << 'EOF'
/* Общие стили для обоих интерфейсов */
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
    margin: 0;
    color: #333;
}

.container {
    background: rgba(255, 255, 255, 0.95);
    backdrop-filter: blur(10px);
    border-radius: 20px;
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
    padding: 40px;
    width: 100%;
    max-width: 1200px;
    transition: all 0.3s ease;
}

.logo {
    text-align: center;
    margin-bottom: 30px;
}

.logo h1 {
    color: #333;
    font-size: 2.5em;
    font-weight: 700;
    margin-bottom: 10px;
}

.logo p {
    color: #666;
    font-size: 1.1em;
}

.form-group {
    margin-bottom: 20px;
}

.form-group label {
    display: block;
    margin-bottom: 8px;
    color: #333;
    font-weight: 500;
}

.form-group input, .form-group textarea {
    width: 100%;
    padding: 15px;
    border: 2px solid #e1e5e9;
    border-radius: 10px;
    font-size: 16px;
    transition: all 0.3s ease;
    background: white;
    font-family: inherit;
}

.form-group input:focus, .form-group textarea:focus {
    outline: none;
    border-color: #667eea;
    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
}

.btn {
    width: 100%;
    padding: 15px;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    border: none;
    border-radius: 10px;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s ease;
    margin-bottom: 15px;
}

.btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
}

.error-message {
    color: #e74c3c;
    text-align: center;
    margin: 15px 0;
    padding: 10px;
    border-radius: 8px;
    background: rgba(231, 76, 60, 0.1);
}

.success-message {
    color: #27ae60;
    text-align: center;
    margin: 15px 0;
    padding: 10px;
    border-radius: 8px;
    background: rgba(39, 174, 96, 0.1);
}

.notification {
    position: fixed;
    top: 20px;
    right: 20px;
    padding: 15px 25px;
    border-radius: 10px;
    color: white;
    font-weight: 500;
    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
    z-index: 2000;
    transform: translateX(150%);
    transition: transform 0.4s ease;
}

.notification.show {
    transform: translateX(0);
}

.notification.success {
    background: #27ae60;
}

.notification.error {
    background: #e74c3c;
}

@media (max-width: 768px) {
    .container {
        padding: 20px;
    }
}
EOF

# 10. Create JavaScript for admin panel
mkdir -p public/js
cat > public/js/admin.js << 'EOF'
document.addEventListener('DOMContentLoaded', () => {
    // Элементы админ-панели
    const adminUsername = document.getElementById('admin-username');
    const logoutBtn = document.getElementById('admin-logout');
    const navButtons = document.querySelectorAll('.nav-btn');
    const sections = document.querySelectorAll('.admin-section');
    const notification = document.getElementById('admin-notification');
    
    // Переменные состояния
    let currentPage = {
        users: 1,
        logs: 1
    };
    
    // Инициализация
    checkAdminAuth();
    setupEventListeners();
    
    // Проверка аутентификации и прав администратора
    function checkAdminAuth() {
        fetch('/api/auth/check')
            .then(response => response.json())
            .then(data => {
                if (data.authenticated && data.isAdmin) {
                    adminUsername.textContent = data.username;
                    loadDashboard();
                } else {
                    window.location.href = '/';
                }
            })
            .catch(error => showNotification('Ошибка сети', 'error'));
    }
    
    // Настройка обработчиков событий
    function setupEventListeners() {
        // Навигация
        navButtons.forEach(button => {
            button.addEventListener('click', () => {
                const target = button.getAttribute('data-target');
                
                // Обновить активную кнопку
                navButtons.forEach(btn => btn.classList.remove('active'));
                button.classList.add('active');
                
                // Показать активную секцию
                sections.forEach(section => {
                    section.classList.remove('active');
                    if (section.id === target) {
                        section.classList.add('active');
                        
                        // Загрузить данные при первом открытии
                        if (target === 'users' && !document.querySelector('#users-table tbody').innerHTML) {
                            loadUsers();
                        } else if (target === 'logs' && !document.querySelector('#logs-table tbody').innerHTML) {
                            loadLogs();
                        }
                    }
                });
            });
        });
        
        // Выход
        logoutBtn.addEventListener('click', logoutAdmin);
        
        // Закрытие модального окна
        document.getElementById('close-user-modal').addEventListener('click', closeUserModal);
        document.getElementById('cancel-reset').addEventListener('click', closeUserModal);
    }
    
    // Загрузка дашборда
    function loadDashboard() {
        // Загрузка статистики
        fetch('/api/admin/stats')
            .then(response => response.json())
            .then(stats => {
                renderStats(stats);
            })
            .catch(error => showNotification('Ошибка загрузки статистики', 'error'));
        
        // Загрузка последних пользователей
        fetch('/api/admin/users?limit=5')
            .then(response => response.json())
            .then(users => {
                renderRecentUsers(users);
            })
            .catch(error => showNotification('Ошибка загрузки пользователей', 'error'));
    }
    
    // Отображение статистики
    function renderStats(stats) {
        const statsGrid = document.getElementById('stats-grid');
        statsGrid.innerHTML = '';
        
        const statItems = [
            { label: 'Всего пользователей', value: stats.totalUsers, icon: '👥' },
            { label: 'Активных пользователей', value: stats.activeUsers, icon: '🟢' },
            { label: 'Сохранённых паролей', value: stats.totalPasswords, icon: '🔑' },
            { label: 'Новых за сегодня', value: stats.newUsersToday, icon: '🆕' },
            { label: 'Заблокированных', value: stats.lockedUsers, icon: '🔒' }
        ];
        
        statItems.forEach(item => {
            const statCard = document.createElement('div');
            statCard.className = 'stat-card';
            statCard.innerHTML = `
                <div class="stat-icon">${item.icon}</div>
                <div class="stat-value">${item.value}</div>
                <div class="stat-label">${item.label}</div>
            `;
            statsGrid.appendChild(statCard);
        });
    }
    
    // Отображение последних пользователей
    function renderRecentUsers(users) {
        const tbody = document.querySelector('#recent-users tbody');
        tbody.innerHTML = '';
        
        users.forEach(user => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${user.id}</td>
                <td>${escapeHtml(user.username)}</td>
                <td>${formatDate(user.created_at)}</td>
                <td>${user.last_login ? formatDate(user.last_login) : 'Никогда'}</td>
                <td>${user.password_count}</td>
                <td>${getUserStatus(user)}</td>
            `;
            tbody.appendChild(tr);
        });
    }
    
    // Загрузка пользователей
    function loadUsers(page = 1) {
        currentPage.users = page;
        
        fetch(`/api/admin/users?page=${page}`)
            .then(response => response.json())
            .then(users => {
                renderUsers(users);
                renderUsersPagination(users.length);
            })
            .catch(error => showNotification('Ошибка загрузки пользователей', 'error'));
    }
    
    // Отображение пользователей
    function renderUsers(users) {
        const tbody = document.querySelector('#users-table tbody');
        tbody.innerHTML = '';
        
        users.forEach(user => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${user.id}</td>
                <td>${escapeHtml(user.username)}</td>
                <td>${user.is_admin ? '✅' : '❌'}</td>
                <td>${formatDate(user.created_at)}</td>
                <td>${user.password_count}</td>
                <td>${getUserStatus(user)}</td>
                <td>
                    <button class="action-btn edit-btn" data-id="${user.id}">👁️</button>
                    ${user.locked_until ? `<button class="action-btn unlock-btn" data-id="${user.id}">🔓</button>` : ''}
                    <button class="action-btn delete-btn" data-id="${user.id}">🗑️</button>
                </td>
            `;
            
            // Добавление обработчиков действий
            tr.querySelector('.edit-btn').addEventListener('click', () => viewUserDetails(user.id));
            if (user.locked_until) {
                tr.querySelector('.unlock-btn').addEventListener('click', () => unlockUser(user.id));
            }
            tr.querySelector('.delete-btn').addEventListener('click', () => deleteUser(user.id, user.username));
            
            tbody.appendChild(tr);
        });
    }
    
    // Пагинация пользователей
    function renderUsersPagination(totalUsers) {
        const totalPages = Math.ceil(totalUsers / 10);
        const pagination = document.getElementById('users-pagination');
        pagination.innerHTML = '';
        
        for (let i = 1; i <= totalPages; i++) {
            const button = document.createElement('button');
            button.className = `page-btn ${i === currentPage.users ? 'active' : ''}`;
            button.textContent = i;
            button.addEventListener('click', () => loadUsers(i));
            pagination.appendChild(button);
        }
    }
    
    // Просмотр деталей пользователя
    function viewUserDetails(userId) {
        fetch(`/api/admin/users/${userId}`)
            .then(response => response.json())
            .then(user => {
                openUserModal(user);
            })
            .catch(error => showNotification('Ошибка загрузки данных пользователя', 'error'));
    }
    
    // Открытие модального окна пользователя
    function openUserModal(user) {
        document.getElementById('user-modal-title').textContent = `Пользователь: ${user.username}`;
        
        const userDetails = document.getElementById('user-details');
        userDetails.innerHTML = `
            <div class="user-info">
                <p><strong>ID:</strong> ${user.id}</p>
                <p><strong>Имя пользователя:</strong> ${user.username}</p>
                <p><strong>Администратор:</strong> ${user.is_admin ? 'Да' : 'Нет'}</p>
                <p><strong>Дата регистрации:</strong> ${formatDate(user.created_at)}</p>
                <p><strong>Последний вход:</strong> ${user.last_login ? formatDate(user.last_login) : 'Никогда'}</p>
                <p><strong>Сохранённых паролей:</strong> ${user.password_count}</p>
                <p><strong>Статус:</strong> ${getUserStatus(user)}</p>
                <div class="modal-actions">
                    <button class="btn" id="toggle-admin-btn">
                        ${user.is_admin ? 'Отозвать права админа' : 'Сделать администратором'}
                    </button>
                </div>
            </div>
        `;
        
        // Обработчик изменения прав администратора
        document.getElementById('toggle-admin-btn').addEventListener('click', () => toggleAdminStatus(user.id, !user.is_admin));
        
        // Обработчик сброса пароля
        document.getElementById('reset-password-btn').addEventListener('click', () => resetUserPassword(user.id));
        
        document.getElementById('user-modal').style.display = 'flex';
    }
    
    // Закрытие модального окна пользователя
    function closeUserModal() {
        document.getElementById('user-modal').style.display = 'none';
        document.getElementById('password-reset-error').style.display = 'none';
        document.getElementById('new-password').value = '';
    }
    
    // Изменение статуса администратора
    function toggleAdminStatus(userId, makeAdmin) {
        fetch(`/api/admin/users/${userId}/toggle-admin`, {
            method: 'PUT'
        })
        .then(response => response.json())
        .then(data => {
            if (data.message) {
                showNotification(data.message, 'success');
                closeUserModal();
                loadUsers(currentPage.users);
            } else {
                showNotification('Ошибка изменения прав', 'error');
            }
        })
        .catch(error => showNotification('Ошибка сети', 'error'));
    }
    
    // Сброс пароля пользователя
    function resetUserPassword(userId) {
        const newPassword = document.getElementById('new-password').value;
        
        if (!newPassword || newPassword.length < 8) {
            document.getElementById('password-reset-error').textContent = 'Пароль должен содержать минимум 8 символов';
            document.getElementById('password-reset-error').style.display = 'block';
            return;
        }
        
        fetch(`/api/admin/users/${userId}/password`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: newPassword })
        })
        .then(response => response.json())
        .then(data => {
            if (data.message) {
                showNotification('Пароль успешно сброшен', 'success');
                closeUserModal();
            } else {
                document.getElementById('password-reset-error').textContent = data.error || 'Ошибка сброса пароля';
                document.getElementById('password-reset-error').style.display = 'block';
            }
        })
        .catch(error => {
            document.getElementById('password-reset-error').textContent = 'Ошибка сети';
            document.getElementById('password-reset-error').style.display = 'block';
        });
    }
    
    // Разблокировка пользователя
    function unlockUser(userId) {
        fetch(`/api/admin/users/${userId}/unlock`, {
            method: 'PUT'
        })
        .then(response => response.json())
        .then(data => {
            if (data.message) {
                showNotification('Пользователь разблокирован', 'success');
                loadUsers(currentPage.users);
            } else {
                showNotification('Ошибка разблокировки', 'error');
            }
        })
        .catch(error => showNotification('Ошибка сети', 'error'));
    }
    
    // Удаление пользователя
    function deleteUser(userId, username) {
        if (!confirm(`Вы уверены, что хотите удалить пользователя ${username}? Все его пароли также будут удалены!`)) {
            return;
        }
        
        fetch(`/api/admin/users/${userId}`, {
            method: 'DELETE'
        })
        .then(response => response.json())
        .then(data => {
            if (data.message) {
                showNotification('Пользователь удален', 'success');
                loadUsers(currentPage.users);
            } else {
                showNotification(data.error || 'Ошибка удаления', 'error');
            }
        })
        .catch(error => showNotification('Ошибка сети', 'error'));
    }
    
    // Загрузка логов
    function loadLogs(page = 1) {
        currentPage.logs = page;
        
        fetch(`/api/admin/logs?page=${page}`)
            .then(response => response.json())
            .then(data => {
                renderLogs(data.logs);
                renderLogsPagination(data.pagination);
            })
            .catch(error => showNotification('Ошибка загрузки логов', 'error'));
    }
    
    // Отображение логов
    function renderLogs(logs) {
        const tbody = document.querySelector('#logs-table tbody');
        tbody.innerHTML = '';
        
        logs.forEach(log => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${formatDateTime(log.timestamp)}</td>
                <td>${log.admin_username || 'Система'}</td>
                <td>${getActionDescription(log.action)}</td>
                <td>${log.target_username || 'Н/Д'}</td>
                <td>${log.details || ''}</td>
                <td>${log.ip_address || 'Н/Д'}</td>
            `;
            tbody.appendChild(tr);
        });
    }
    
    // Пагинация логов
    function renderLogsPagination(pagination) {
        const container = document.getElementById('logs-pagination');
        container.innerHTML = '';
        
        for (let i = 1; i <= pagination.pages; i++) {
            const button = document.createElement('button');
            button.className = `page-btn ${i === currentPage.logs ? 'active' : ''}`;
            button.textContent = i;
            button.addEventListener('click', () => loadLogs(i));
            container.appendChild(button);
        }
    }
    
    // Выход администратора
    function logoutAdmin() {
        fetch('/api/logout', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                if (data.message) {
                    window.location.href = '/';
                }
            })
            .catch(error => showNotification('Ошибка выхода', 'error'));
    }
    
    // Вспомогательные функции
    function showNotification(message, type) {
        notification.textContent = message;
        notification.className = `notification ${type} show`;
        
        setTimeout(() => {
            notification.classList.remove('show');
        }, 3000);
    }
    
    function formatDate(dateString) {
        if (!dateString) return 'Н/Д';
        const date = new Date(dateString);
        return date.toLocaleDateString('ru-RU');
    }
    
    function formatDateTime(dateString) {
        if (!dateString) return 'Н/Д';
        const date = new Date(dateString);
        return date.toLocaleString('ru-RU');
    }
    
    function getUserStatus(user) {
        if (user.locked_until && new Date(user.locked_until) > new Date()) {
            return '🔒 Заблокирован';
        }
        return '🟢 Активен';
    }
    
    function getActionDescription(action) {
        const actions = {
            'DELETE_USER': 'Удаление пользователя',
            'RESET_PASSWORD': 'Сброс пароля',
            'GRANT_ADMIN': 'Выдача прав администратора',
            'REVOKE_ADMIN': 'Отзыв прав администратора',
            'UNLOCK_USER': 'Разблокировка пользователя'
        };
        return actions[action] || action;
    }
    
    function escapeHtml(unsafe) {
        return unsafe 
            ? unsafe.toString()
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;")
            : '';
    }
});
EOF

# 11. Set permissions
chmod -R 755 /var/www/password-manager

# 12. Create systemd service
sudo cat > /etc/systemd/system/password-manager.service << EOF
[Unit]
Description=Password Manager Service
After=network.target

[Service]
User=root
WorkingDirectory=/var/www/password-manager
ExecStart=/usr/bin/node server.js
Restart=always
Environment=NODE_ENV=production
Environment=PORT=3000

[Install]
WantedBy=multi-user.target
EOF

# 13. Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable password-manager
sudo systemctl start password-manager

# 14. Print completion message
echo -e "\n\e[1;32mУстановка завершена успешно!\e[0m"
echo -e "\e[1;34mСервис запущен на порту 3000\e[0m"
echo -e "\e[1;33mДанные администратора сохранены в файле: /var/www/password-manager/ADMIN_CREDENTIALS.txt\e[0m"
echo -e "\e[1;35mУправление сервисом:"
echo -e "  sudo systemctl status password-manager"
echo -e "  sudo systemctl restart password-manager\e[0m"
echo -e "\e[1;36mДоступ к приложению: http://$(curl -s ifconfig.me):3000\e[0m\n"