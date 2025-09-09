# Express.js Cheat Sheet

A comprehensive reference for Express.js - a minimal and flexible Node.js web application framework.

---

## Table of Contents
- [Installation and Setup](#installation-and-setup)
- [Basic Application](#basic-application)
- [Routing](#routing)
- [Middleware](#middleware)
- [Request and Response](#request-and-response)
- [Template Engines](#template-engines)
- [Static Files](#static-files)
- [Error Handling](#error-handling)
- [Security](#security)
- [Database Integration](#database-integration)
- [Authentication](#authentication)
- [Testing](#testing)
- [Best Practices](#best-practices)

---

## Installation and Setup

### Installation
```bash
# Create new project
mkdir my-express-app
cd my-express-app
npm init -y

# Install Express
npm install express

# Install common middleware
npm install cors helmet morgan body-parser cookie-parser

# Development dependencies
npm install --save-dev nodemon
```

### Basic Package.json Scripts
```json
{
  "scripts": {
    "start": "node app.js",
    "dev": "nodemon app.js",
    "test": "jest"
  }
}
```

## Basic Application

### Minimal Express Server
```javascript
const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

// Basic route
app.get('/', (req, res) => {
  res.send('Hello, Express!');
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
```

### Application Structure
```javascript
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');

const app = express();

// Global middleware
app.use(helmet()); // Security headers
app.use(cors()); // Enable CORS
app.use(morgan('combined')); // Logging
app.use(express.json({ limit: '10mb' })); // Parse JSON bodies
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded bodies

// Routes
app.use('/api/users', require('./routes/users'));
app.use('/api/posts', require('./routes/posts'));

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

module.exports = app;
```

## Routing

### Basic Routes
```javascript
const express = require('express');
const app = express();

// HTTP methods
app.get('/', (req, res) => {
  res.send('GET request');
});

app.post('/', (req, res) => {
  res.send('POST request');
});

app.put('/', (req, res) => {
  res.send('PUT request');
});

app.delete('/', (req, res) => {
  res.send('DELETE request');
});

// Multiple methods
app.route('/users')
  .get((req, res) => {
    res.send('Get users');
  })
  .post((req, res) => {
    res.send('Create user');
  })
  .put((req, res) => {
    res.send('Update user');
  });
```

### Route Parameters
```javascript
// Route parameters
app.get('/users/:id', (req, res) => {
  const userId = req.params.id;
  res.json({ userId });
});

// Multiple parameters
app.get('/users/:userId/posts/:postId', (req, res) => {
  const { userId, postId } = req.params;
  res.json({ userId, postId });
});

// Optional parameters
app.get('/posts/:year/:month?', (req, res) => {
  const { year, month } = req.params;
  res.json({ year, month: month || 'all' });
});

// Wildcard routes
app.get('/files/*', (req, res) => {
  const filePath = req.params[0];
  res.json({ filePath });
});

// Pattern matching
app.get('/users/:id(\\d+)', (req, res) => {
  // Only matches numeric IDs
  res.json({ id: req.params.id });
});
```

### Router Module
```javascript
// routes/users.js
const express = require('express');
const router = express.Router();

// Middleware specific to this router
router.use((req, res, next) => {
  console.log('Users route accessed');
  next();
});

// Routes
router.get('/', async (req, res) => {
  try {
    const users = await User.find();
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/', async (req, res) => {
  try {
    const user = new User(req.body);
    await user.save();
    res.status(201).json(user);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

router.put('/:id', async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id, 
      req.body, 
      { new: true, runValidators: true }
    );
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

router.delete('/:id', async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
```

## Middleware

### Built-in Middleware
```javascript
const express = require('express');
const app = express();

// Parse JSON bodies
app.use(express.json({ limit: '50mb' }));

// Parse URL-encoded bodies
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Serve static files
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
```

### Third-party Middleware
```javascript
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const rateLimit = require('express-rate-limit');

// CORS configuration
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? 'https://yourdomain.com' 
    : 'http://localhost:3000',
  credentials: true
}));

// Security headers
app.use(helmet());

// Request logging
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

// Gzip compression
app.use(compression());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);
```

### Custom Middleware
```javascript
// Authentication middleware
function requireAuth(req, res, next) {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(400).json({ error: 'Invalid token.' });
  }
}

// Request logging middleware
function requestLogger(req, res, next) {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`${req.method} ${req.path} - ${res.statusCode} - ${duration}ms`);
  });
  
  next();
}

// Validation middleware
function validateUser(req, res, next) {
  const { name, email } = req.body;
  
  if (!name || !email) {
    return res.status(400).json({
      error: 'Name and email are required'
    });
  }
  
  if (!/\S+@\S+\.\S+/.test(email)) {
    return res.status(400).json({
      error: 'Invalid email format'
    });
  }
  
  next();
}

// Usage
app.use(requestLogger);
app.post('/api/users', validateUser, requireAuth, (req, res) => {
  // Route handler
});
```

## Request and Response

### Request Object
```javascript
app.get('/api/example', (req, res) => {
  // Query parameters (?name=john&age=25)
  const { name, age } = req.query;
  
  // Route parameters (/users/:id)
  const { id } = req.params;
  
  // Request body (POST/PUT requests)
  const userData = req.body;
  
  // Headers
  const contentType = req.get('Content-Type');
  const userAgent = req.get('User-Agent');
  
  // Request information
  console.log('Method:', req.method);
  console.log('URL:', req.url);
  console.log('Path:', req.path);
  console.log('Protocol:', req.protocol);
  console.log('IP:', req.ip);
  console.log('Cookies:', req.cookies);
  
  // Check request type
  if (req.is('json')) {
    console.log('JSON request');
  }
  
  res.json({ message: 'Request processed' });
});
```

### Response Object
```javascript
app.get('/api/response-examples', (req, res) => {
  // Set status code
  res.status(200);
  
  // Set headers
  res.set('X-Custom-Header', 'value');
  res.set({
    'Content-Type': 'application/json',
    'X-Powered-By': 'Express'
  });
  
  // Different response methods
  // res.send('Plain text or HTML');
  // res.json({ data: 'JSON response' });
  // res.redirect('/new-path');
  // res.render('template', { data });
  // res.download('/path/to/file.pdf');
  // res.sendFile(path.join(__dirname, 'file.html'));
  
  // Method chaining
  res.status(201).json({
    message: 'Created successfully',
    timestamp: new Date().toISOString()
  });
});

// Response with cookies
app.post('/login', (req, res) => {
  // Set cookie
  res.cookie('token', 'jwt-token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  });
  
  res.json({ message: 'Logged in successfully' });
});

// Clear cookie
app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out successfully' });
});
```

## Template Engines

### EJS Template Engine
```bash
# Install EJS
npm install ejs
```

```javascript
// Set up EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Render template
app.get('/users/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    res.render('user', { 
      title: 'User Profile',
      user: user,
      currentYear: new Date().getFullYear()
    });
  } catch (error) {
    res.status(500).render('error', { error });
  }
});
```

```html
<!-- views/user.ejs -->
<!DOCTYPE html>
<html>
<head>
    <title><%= title %></title>
</head>
<body>
    <h1>Welcome, <%= user.name %>!</h1>
    <p>Email: <%= user.email %></p>
    
    <% if (user.isAdmin) { %>
        <p>Admin privileges granted</p>
    <% } %>
    
    <ul>
    <% user.hobbies.forEach(hobby => { %>
        <li><%= hobby %></li>
    <% }); %>
    </ul>
    
    <footer>&copy; <%= currentYear %></footer>
</body>
</html>
```

### Handlebars Template Engine
```bash
# Install Handlebars
npm install express-handlebars
```

```javascript
const exphbs = require('express-handlebars');

// Set up Handlebars
app.engine('handlebars', exphbs.engine());
app.set('view engine', 'handlebars');

// Custom helper
app.engine('handlebars', exphbs.engine({
  helpers: {
    formatDate: function(date) {
      return new Date(date).toLocaleDateString();
    }
  }
}));
```

## Static Files

### Serving Static Files
```javascript
// Serve static files from 'public' directory
app.use(express.static('public'));

// Serve with virtual path
app.use('/static', express.static('public'));

// Serve from multiple directories
app.use(express.static('public'));
app.use(express.static('files'));

// Static files with options
app.use(express.static('public', {
  dotfiles: 'deny',
  etag: false,
  extensions: ['htm', 'html'],
  index: false,
  maxAge: '1d',
  redirect: false,
  setHeaders: (res, path, stat) => {
    res.set('x-timestamp', Date.now());
  }
}));
```

## Error Handling

### Error Handling Middleware
```javascript
// Async error wrapper
function asyncWrapper(fn) {
  return function(req, res, next) {
    fn(req, res, next).catch(next);
  };
}

// Usage with async routes
app.get('/users/:id', asyncWrapper(async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) {
    const error = new Error('User not found');
    error.status = 404;
    throw error;
  }
  res.json(user);
}));

// Global error handling middleware (must be last)
app.use((err, req, res, next) => {
  // Log error
  console.error(err.stack);
  
  // Set default error values
  const status = err.status || err.statusCode || 500;
  const message = err.message || 'Internal Server Error';
  
  // Send error response
  if (process.env.NODE_ENV === 'production') {
    res.status(status).json({
      error: status >= 500 ? 'Internal Server Error' : message
    });
  } else {
    res.status(status).json({
      error: message,
      stack: err.stack
    });
  }
});

// 404 handler (must be after all routes)
app.use('*', (req, res) => {
  res.status(404).json({
    error: `Route ${req.originalUrl} not found`
  });
});
```

### Custom Error Classes
```javascript
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;
    
    Error.captureStackTrace(this, this.constructor);
  }
}

class ValidationError extends AppError {
  constructor(message, field) {
    super(message, 400);
    this.field = field;
  }
}

// Usage
app.get('/users/:id', asyncWrapper(async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) {
    throw new AppError('User not found', 404);
  }
  res.json(user);
}));
```

## Security

### Security Best Practices
```javascript
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');

// Security headers
app.use(helmet());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP'
});
app.use('/api/', limiter);

// Data sanitization against NoSQL injection
app.use(mongoSanitize());

// Data sanitization against XSS
app.use(xss());

// Prevent parameter pollution
app.use(hpp({
  whitelist: ['sort', 'fields', 'page', 'limit']
}));

// Input validation
function validateInput(req, res, next) {
  const { email, password } = req.body;
  
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Invalid email' });
  }
  
  if (!password || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  
  next();
}
```

## Database Integration

### MongoDB with Mongoose
```javascript
const mongoose = require('mongoose');

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// User model
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// CRUD operations
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/users', async (req, res) => {
  try {
    const user = new User(req.body);
    await user.save();
    res.status(201).json(user);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
```

### PostgreSQL with Sequelize
```javascript
const { Sequelize, DataTypes } = require('sequelize');

// Initialize Sequelize
const sequelize = new Sequelize(process.env.DATABASE_URL);

// User model
const User = sequelize.define('User', {
  name: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: {
      isEmail: true,
    },
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

// Sync database
sequelize.sync();

// CRUD operations
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.findAll({
      attributes: { exclude: ['password'] }
    });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
```

## Authentication

### JWT Authentication
```javascript
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

// Register endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const user = new User({
      name,
      email,
      password: hashedPassword
    });
    
    await user.save();
    
    // Generate JWT
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.status(201).json({
      message: 'User created successfully',
      token,
      user: { id: user._id, name: user.name, email: user.email }
    });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate JWT
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({
      message: 'Login successful',
      token,
      user: { id: user._id, name: user.name, email: user.email }
    });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Auth middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

// Protected route
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
```

## Testing

### Testing with Jest and Supertest
```javascript
// tests/app.test.js
const request = require('supertest');
const app = require('../app');

describe('Express App', () => {
  test('GET / should return 200', async () => {
    const response = await request(app)
      .get('/')
      .expect(200);
    
    expect(response.body.message).toBe('Hello, Express!');
  });
  
  test('POST /api/users should create user', async () => {
    const userData = {
      name: 'John Doe',
      email: 'john@example.com',
      password: 'password123'
    };
    
    const response = await request(app)
      .post('/api/users')
      .send(userData)
      .expect(201);
    
    expect(response.body.user.name).toBe('John Doe');
  });
  
  test('GET /api/users/:id should return user', async () => {
    const response = await request(app)
      .get('/api/users/1')
      .expect(200);
    
    expect(response.body).toHaveProperty('id');
  });
});
```

## Best Practices

### Project Structure
```
project/
├── controllers/
│   ├── authController.js
│   └── userController.js
├── middleware/
│   ├── auth.js
│   └── validation.js
├── models/
│   └── User.js
├── routes/
│   ├── auth.js
│   └── users.js
├── utils/
│   └── helpers.js
├── config/
│   └── database.js
├── tests/
├── app.js
└── server.js
```

### Environment Configuration
```javascript
// config/config.js
module.exports = {
  port: process.env.PORT || 3000,
  mongoUri: process.env.MONGODB_URI || 'mongodb://localhost:27017/myapp',
  jwtSecret: process.env.JWT_SECRET || 'fallback-secret',
  nodeEnv: process.env.NODE_ENV || 'development'
};

// .env file
NODE_ENV=development
PORT=3000
MONGODB_URI=mongodb://localhost:27017/myapp
JWT_SECRET=your-secret-key
```

### Performance Tips
```javascript
// Enable compression
const compression = require('compression');
app.use(compression());

// Use connection pooling for database
const mongoose = require('mongoose');
mongoose.connect(uri, {
  maxPoolSize: 10,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
});

// Cache control for static assets
app.use('/static', express.static('public', {
  maxAge: '1y',
  etag: false
}));

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received');
  server.close(() => {
    console.log('Process terminated');
  });
});
```

---

## Common Middleware

| Middleware | Purpose | Installation |
|------------|---------|-------------|
| `helmet` | Security headers | `npm install helmet` |
| `cors` | Cross-origin requests | `npm install cors` |
| `morgan` | HTTP request logging | `npm install morgan` |
| `compression` | Response compression | `npm install compression` |
| `express-rate-limit` | Rate limiting | `npm install express-rate-limit` |

## Deployment

### Production Setup
```bash
# Environment variables
export NODE_ENV=production
export PORT=8080

# Process manager (PM2)
npm install -g pm2
pm2 start app.js --name "my-app"
pm2 startup
pm2 save

# Docker
FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["node", "app.js"]
```

---

## Resources
- [Official Express.js Documentation](https://expressjs.com)
- [Express.js Guide](https://expressjs.com/en/guide/routing.html)
- [Awesome Express](https://github.com/rajikaimal/awesome-express)
- [Express.js Best Practices](https://github.com/goldbergyoni/nodebestpractices)
- [MDN Express Tutorial](https://developer.mozilla.org/en-US/docs/Learn/Server-side/Express_Nodejs)

---
*Originally compiled from various sources. Contributions welcome!*