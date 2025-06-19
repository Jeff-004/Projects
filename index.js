import express from "express";
import bodyParser from "body-parser";
import { Client } from "pg";
import dotenv from "dotenv";
import bcrypt from 'bcrypt';
import passport from 'passport';
import LocalStrategy from 'passport-local';
import session from 'express-session';

dotenv.config();

const app = express();
const port = 3000;

const db = new Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

db.connect();

// Session config
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
}));


app.use(passport.initialize());
app.use(passport.session());

app.use((req, res, next) => {
  res.locals.user = req.user || null; // Makes user available in all templates
  next();
});


// Passport local strategy
passport.use(new LocalStrategy(async (username, password, done) => {
  try {
    const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return done(null, false, { message: 'Invalid username or password' });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return done(null, false, { message: 'Invalid username or password' });
    }

    return done(null, user);
  } catch (error) {
    return done(error);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const result = await db.query('SELECT * FROM users WHERE id = $1', [id]);
    if (result.rows.length === 0) return done(null, false);
    done(null, result.rows[0]);
  } catch (error) {
    done(error);
  }
});

// Middleware to check if user is authenticated
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/sign-in');
}

// ROUTES

// Home
app.get('/', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM posts ORDER BY id DESC');
    res.render('home', { posts: result.rows });
  } catch (error) {
    res.render('home', { posts: [] });
  }
});

app.get('/posts/:id', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM posts WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).send('Post not found');
    }
    res.render('post', { post: result.rows[0] });
  } catch (error) {
    res.status(500).send('Server error');
  }
});


// About
app.get('/about', (req, res) => {
  res.render('about');
});

// Register
app.get('/register', (req, res) => {
  res.render('register');
});


app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).render('register', { error: 'Username and password are required.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Insert user and return their ID
    const result = await db.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username',
      [username, hashedPassword]
    );

    // Automatically log in the new user
    const user = result.rows[0];
    req.login(user, (err) => {
      if (err) {
        console.error('Auto-login error:', err);
        return res.redirect('/sign-in');
      }
      return res.redirect('/welcome.html');
    });
    
  } catch (error) {
    if (error.code === '23505') {
      return res.redirect('/sign-in?error=Username already exists. Please sign in');
    }
    res.status(500).render('register', { error: 'Internal server error.' });
  }
});


// Sign-In
app.get('/sign-in', (req, res) => {
  if (req.isAuthenticated()) return res.redirect('/welcome');
  res.render('sign-in');
});

app.post('/sign-in', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) return next(err);
    if (!user) {
      // Render the sign-in page with an error message
      return res.status(401).render('sign-in', { error: info.message });
    }
    req.logIn(user, (err) => {
      if (err) return next(err);
      return res.redirect('/welcome');
    });
  })(req, res, next);
});

//Sign out
app.post('/sign-out', (req, res, next) => {
  req.logout((err) => {
    if (err) { return next(err); }
    res.redirect('/');  // Redirect user after logout
  });
});


// Write (Protected)
app.get('/write', ensureAuthenticated, (req, res) => {
  res.render('write', { error: null, success: null });
});

app.post('/write', ensureAuthenticated, async (req, res) => {
  const { title, content } = req.body;
  if (!title || !content) {
    return res.status(400).render('write', {
      error: 'Title and content are required.',
      success: null
    });
  }
  try {
    await db.query(
  'INSERT INTO posts (title, content, author) VALUES ($1, $2, $3)',
  [title, content, req.user.username]
);

    res.status(200).render('write', {
      success: 'Post created successfully!',
      error: null
    });
  } catch (error) {
    res.status(500).render('write', {
      error: 'Internal server error.',
      success: null
    });
  }
});

// Welcome
app.get('/welcome', (req, res) => {
  res.redirect('/welcome.html');
});


// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
