import path from 'node:path';
import pg from 'pg';
import express from 'express';
import session from 'express-session';
import passport from 'passport';
import passportLocal from 'passport-local';
import 'dotenv/config';

const PORT = process.env.PORT;
const DB = process.env.DB;
const SECRET = process.env.SECRET;

const LocalStrategy = passportLocal.Strategy;

const pool = new pg.Pool({
  connectionString: DB,
});

const app = express();
app.set('view engine', 'ejs');

app.use(
  session({
    secret: SECRET,
    resave: false,
    saveUninitialized: false,
  }),
);

app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.get('/', (req, res) => {
  res.render('index', { title: 'Index' });
});

app.get('/sign-up', (req, res) => {
  res.render('sign-up-form', { title: 'Sign up' });
});

app.post('/sign-up', async (req, res, next) => {
  try {
    const { username, password } = req.body;
    await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2);',
      [username, password],
    );
    res.redirect('/');
  } catch (error) {
    next(error);
  }
});

app.use((error, req, res, next) => {
  res.send(error);
});

app.listen(PORT, () => console.log('app listening on port', PORT));
