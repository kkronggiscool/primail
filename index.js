// Existing imports and middleware
const express = require('express');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// Path to user and email data files
const usersFilePath = 'users.json';
const emailsFilePath = 'emails.json';

// Load or initialize users.json
let users = {};
if (fs.existsSync(usersFilePath)) {
  try {
    const data = fs.readFileSync(usersFilePath, 'utf8');
    users = data ? JSON.parse(data) : {}; // Handle empty file
  } catch (err) {
    console.error('Error reading or parsing users.json:', err);
    users = {}; // Fallback to empty object
  }
} else {
  fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
}

// Load or initialize emails.json
let emails = {};
if (fs.existsSync(emailsFilePath)) {
  try {
    const data = fs.readFileSync(emailsFilePath, 'utf8');
    emails = data ? JSON.parse(data) : {}; // Handle empty file
  } catch (err) {
    console.error('Error reading or parsing emails.json:', err);
    emails = {}; // Fallback to empty object
  }
} else {
  fs.writeFileSync(emailsFilePath, JSON.stringify(emails, null, 2));
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: '8beb13b7ca647b5eda2d618d10412528bebef69d250cb7b80b2ac2746cba051f5894f3e541e4582f6eacc4df5eba34c4243c03cc68a20212816cc9b4e6edb9ab', // Your secret key
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Set to true if using HTTPS
}));

// Serve favicon
app.use('/favicon.ico', express.static(path.join(__dirname, 'public', 'favicon.png')));

// Serve static files (e.g., CSS)
app.use(express.static('public'));

// Helper functions
function writeUsers() {
  try {
    fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
  } catch (err) {
    console.error('Error writing to users.json:', err);
  }
}

function writeEmails() {
  try {
    fs.writeFileSync(emailsFilePath, JSON.stringify(emails, null, 2));
  } catch (err) {
    console.error('Error writing to emails.json:', err);
  }
}

// Middleware to check if user is logged in
function checkAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

// Login Page Route
app.get('/login', (req, res) => {
  const message = req.query.message || '';
  res.send(`
    <link rel="stylesheet" href="/styles.css">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">
    <title>Primail - Login</title>
    <div class="login-signup">
      <h1>Login</h1>
      ${message ? `<p class="error">${message}</p>` : ''}
      <form method="POST" action="/login">
        <label for="email">Email:</label>
        <input type="email" id="email" name="email" required>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>
        <button type="submit">Login</button>
        <p>Don't have an account? <a href="/signup">Sign up</a></p>
      </form>
    </div>
  `);
});

// Signup Page Route
app.get('/signup', (req, res) => {
  const message = req.query.message || '';
  res.send(`
    <link rel="stylesheet" href="/styles.css">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">
    <title>Primail - Sign Up</title>
    <div class="login-signup">
      <h1>Sign Up</h1>
      ${message ? `<p class="error">${message}</p>` : ''}
      <form method="POST" action="/signup">
        <label for="email">Email:</label>
        <input type="email" id="email" name="email" required>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>
        <button type="submit">Sign Up</button>
        <p>Already have an account? <a href="/login">Login</a></p>
      </form>
    </div>
  `);
});

// Signup Route
app.post('/signup', (req, res) => {
  const { email, password } = req.body;

  if (!email.endsWith('@primary.com')) {
    return res.redirect('/signup?message=Email%20must%20end%20with%20@primary.com');
  }

  if (users[email]) {
    return res.redirect('/signup?message=Email%20already%20registered');
  }

  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) return res.redirect('/signup?message=Error%20hashing%20password');

    users[email] = { password: hashedPassword, id: uuidv4() };
    writeUsers(); // Save to file

    // Redirect to login page
    res.redirect('/login');
  });
});

// Login Route
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!users[email]) {
    return res.redirect('/login?message=Invalid%20email%20or%20password');
  }

  bcrypt.compare(password, users[email].password, (err, isMatch) => {
    if (err) return res.redirect('/login?message=Error%20comparing%20passwords');
    if (!isMatch) return res.redirect('/login?message=Invalid%20email%20or%20password');

    req.session.user = { email };
    res.redirect('/inbox');
  });
});

// Logout Route
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ message: 'Error logging out' });
    res.redirect('/login');
  });
});

// Inbox Route (Protected)
app.get('/inbox', checkAuth, (req, res) => {
  const searchQuery = req.query.search || '';
  const userEmails = Object.values(emails)
    .filter(email => email.to === req.session.user.email && email.from !== req.session.user.email)
    .filter(email => email.subject.toLowerCase().includes(searchQuery.toLowerCase()))
    .sort((a, b) => new Date(b.date) - new Date(a.date)) // New emails at the top
    .map(email => `
      <div class="email ${email.read ? 'read' : 'unread'}">
        <a href="/e/${email.id}">
          <strong>From: ${email.from}</strong> - ${email.subject}
          <br>
          <small>${new Date(email.date).toLocaleString()}</small>
        </a>
      </div>
    `)
    .join('');

  const noEmailsMessage = userEmails.length === 0 ? '<p class="no-emails">No ones here for you yet.. :(</p>' : '';

  res.send(`
    <link rel="stylesheet" href="/styles.css">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">
    <title>Primail - Inbox</title>
    <div class="container">
      <div class="sidebar">
        <h1>Primal</h1>
        <button id="compose" class="sidebar-item">Compose</button>
        <a href="/inbox" class="sidebar-item">Inbox</a>
        <a href="/sent" class="sidebar-item">Sent</a>
        <a href="/logout" class="sidebar-item">Logout</a>
        <div id="compose-popup" class="hidden">
          <form id="compose-form" method="POST" action="/send-email">
            <label for="to">To:</label>
            <input type="email" id="to" name="to" placeholder="Recipient's email" required>
            <label for="subject">Subject:</label>
            <input type="text" id="subject" name="subject" placeholder="Subject" required>
            <label for="message">Message:</label>
            <textarea id="message" name="message" placeholder="Message" required></textarea>
            <button type="submit">Send my precious email</button>
          </form>
        </div>
      </div>
      <div class="main-content">
        <div class="user-info">
          <p>Logged in as: ${req.session.user.email}</p>
          <p class="email-list">
            <form method="GET" action="/inbox">
              <input type="text" name="search" placeholder="Search Mail" value="${searchQuery}">
              <button type="submit">Search</button>
            </form>
          </p>
        </div>
        ${noEmailsMessage}
        ${userEmails}
      </div>
    </div>
    <script>
      document.getElementById('compose').addEventListener('click', () => {
        const popup = document.getElementById('compose-popup');
        popup.classList.toggle('hidden');
      });
    </script>
  `);
});

// Email Details Route (Protected)
app.get('/e/:id', checkAuth, (req, res) => {
  const emailId = req.params.id;
  const email = emails[emailId];

  if (!email) {
    return res.status(404).send('Email not found');
  }

  // Mark email as read
  email.read = true;
  writeEmails();

  res.send(`
    <link rel="stylesheet" href="/styles.css">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">
    <title>Primail - Email Details</title>
    <div class="container">
      <div class="sidebar">
        <h1>Primal</h1>
        <button id="compose" class="sidebar-item">Compose</button>
        <a href="/inbox" class="sidebar-item">Inbox</a>
        <a href="/sent" class="sidebar-item">Sent</a>
        <a href="/logout" class="sidebar-item">Logout</a>
        <div id="compose-popup" class="hidden">
          <form id="compose-form" method="POST" action="/send-email">
            <label for="to">To:</label>
            <input type="email" id="to" name="to" placeholder="Recipient's email" required>
            <label for="subject">Subject:</label>
            <input type="text" id="subject" name="subject" placeholder="Subject" required>
            <label for="message">Message:</label>
            <textarea id="message" name="message" placeholder="Message" required></textarea>
            <button type="submit">Send my precious email</button>
          </form>
        </div>
      </div>
      <div class="main-content">
        <h2>Email Details</h2>
        <p><strong>From:</strong> ${email.from}</p>
        <p><strong>To:</strong> ${email.to}</p>
        <p><strong>Subject:</strong> ${email.subject}</p>
        <p><strong>Date:</strong> ${new Date(email.date).toLocaleString()}</p>
        <p><strong>Message:</strong></p>
        <p>${email.message}</p>
        <a href="/inbox">Back to Inbox</a>
      </div>
    </div>
    <script>
      document.getElementById('compose').addEventListener('click', () => {
        const popup = document.getElementById('compose-popup');
        popup.classList.toggle('hidden');
      });
    </script>
  `);
});

// Sent Mail Route (Protected)
app.get('/sent', checkAuth, (req, res) => {
  const searchQuery = req.query.search || '';
  const userEmails = Object.values(emails)
    .filter(email => email.from === req.session.user.email)
    .filter(email => email.subject.toLowerCase().includes(searchQuery.toLowerCase()))
    .sort((a, b) => new Date(b.date) - new Date(a.date)) // New emails at the top
    .map(email => `
      <div class="email">
        <a href="/e/${email.id}">
          <strong>To: ${email.to}</strong> - ${email.subject}
          <br>
          <small>${new Date(email.date).toLocaleString()}</small>
        </a>
      </div>
    `)
    .join('');

  const noEmailsMessage = userEmails.length === 0 ? '<p class="no-emails">No sent emails yet.. :(</p>' : '';

  res.send(`
    <link rel="stylesheet" href="/styles.css">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">
    <title>Primail - Sent</title>
    <div class="container">
      <div class="sidebar">
        <h1>Primal</h1>
        <button id="compose" class="sidebar-item">Compose</button>
        <a href="/inbox" class="sidebar-item">Inbox</a>
        <a href="/sent" class="sidebar-item">Sent</a>
        <a href="/logout" class="sidebar-item">Logout</a>
        <div id="compose-popup" class="hidden">
          <form id="compose-form" method="POST" action="/send-email">
            <label for="to">To:</label>
            <input type="email" id="to" name="to" placeholder="Recipient's email" required>
            <label for="subject">Subject:</label>
            <input type="text" id="subject" name="subject" placeholder="Subject" required>
            <label for="message">Message:</label>
            <textarea id="message" name="message" placeholder="Message" required></textarea>
            <button type="submit">Send my precious email</button>
          </form>
        </div>
      </div>
      <div class="main-content">
        <div class="user-info">
          <p>Logged in as: ${req.session.user.email}</p>
          <p class="email-list">
            <form method="GET" action="/sent">
              <input type="text" name="search" placeholder="Search Mail" value="${searchQuery}">
              <button type="submit">Search</button>
            </form>
          </p>
        </div>
        ${noEmailsMessage}
        ${userEmails}
      </div>
    </div>
    <script>
      document.getElementById('compose').addEventListener('click', () => {
        const popup = document.getElementById('compose-popup');
        popup.classList.toggle('hidden');
      });
    </script>
  `);
});

// Send Email Route (Protected)
app.post('/send-email', checkAuth, (req, res) => {
  const { to, subject, message } = req.body;

  if (!users[to]) {
    return res.redirect('/compose?message=Recipient%20email%20not%20found');
  }

  const emailId = uuidv4();
  const newEmail = { id: emailId, from: req.session.user.email, to, subject, message, date: new Date(), read: false };

  // Save to both inbox and sent
  emails[emailId] = newEmail;
  writeEmails();

  res.redirect('/sent');
});

// Mark Email as Read Route
app.post('/mark-read', checkAuth, (req, res) => {
  const { id } = req.body;
  const email = emails[id];

  if (email) {
    email.read = true;
    writeEmails();
  }

  res.status(200).end();
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
