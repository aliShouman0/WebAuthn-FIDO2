const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config();

const db = require('./db');
const registerRoutes = require('./routes/register');
const loginRoutes = require('./routes/login');

const app = express();
const PORT = 3000;


// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static('public'));



// Security Logging Middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  const method = req.method;
  const path = req.path;

  console.log(`[${timestamp}] ${method} ${path}`);


  // Capture response to log results
  const originalSend = res.send;
  res.send = function(data) {
    try {
      if (typeof data === 'string') {
        const parsedData = JSON.parse(data);
        if (parsedData.verified) {
          console.log(`  ✓ Security check PASSED`);
        } else if (parsedData.error) {
          console.log(`  ✗ Error: ${parsedData.error}`);
        }
      }
    } catch (e) {
      // Not JSON, skip logging
    }
    return originalSend.call(this, data);
  };

  next();
});



// Authentication Routes
app.use('/api', registerRoutes);
app.use('/api', loginRoutes);


// Protected Endpoint (Requires Valid Token)
app.get('/api/me', (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {

    // Decode token (simple Base64 decode in production use JWT)
    const decoded = Buffer.from(token, 'base64').toString();
    const [userId, timestamp] = decoded.split(':');

    if (!userId || !timestamp) {
      return res.status(401).json({ error: 'Invalid token format' });
    }

    // Get user info from database
    db.get('SELECT id, username FROM users WHERE id = ?', [userId], (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      if (!user) {
        return res.status(401).json({ error: 'User not found' });
      }

      console.log(`  ✓ Protected endpoint accessed by user ${userId}`);

      res.json({
        authenticated: true,
        userId: user.id,
        username: user.username,
        message: 'This is a protected endpoint - you are authenticated!',
        timestamp: new Date().toISOString()
      });
    });

  } catch (error) {
    res.status(401).json({ error: 'Invalid token: ' + error.message });
  }
});


// Health Check Endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'Server is running', timestamp: new Date().toISOString() });
});  


// 404 Handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});


// Start Server

app.listen(PORT, () => {
  console.log('\n' + '='.repeat(50));
  console.log('🔐 WebAuthn Demo Server Started');
  console.log('='.repeat(50));
  console.log(`Server running at: http://localhost:${PORT}`);
  console.log(`Database: webauthn.db`);
  console.log('\nAvailable endpoints:');
  console.log('  POST /api/register/options   Get registration challenge');
  console.log('  POST /api/register/verify    Verify registration');
  console.log('  POST /api/login/options      Get login challenge');
  console.log('  POST /api/login/verify       Verify login');
  console.log('  GET  /api/me                 Protected endpoint (requires token)');
  console.log('  GET  /api/health             Health check');
  console.log('='.repeat(50) + '\n');
});

module.exports = app;

