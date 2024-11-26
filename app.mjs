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

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query(
        'SELECT * FROM users WHERE username = $1',
        [username],
      );
      const user = rows[0];

      if (!user) {
        return done(null, false, { message: 'Incorrect username' });
      }
      if (user.password !== password) {
        return done(null, false, { message: 'Incorrect password' });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }),
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [
      id,
    ]);
    const user = rows[0];

    done(null, user);
  } catch (err) {
    done(err);
  }
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
app.use((req, res, next) => {
  res.locals.currentUser = req.user;
  next();
});
app.use(express.urlencoded({ extended: false }));

app.get('/', (req, res) => {
  res.render('index', { title: 'Index', user: res.locals.currentUser });
});

app.get('/sign-up', (req, res) => {
  res.render('sign-up-form', { title: 'Sign up' });
});

app.get('/log-out', (req, res, next) => {
  req.logOut((error) => {
    if (error) return next(error);
    res.status(303).redirect('/');
  });
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

app.post(
  '/log-in',
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/',
  }),
);

app.use((error, req, res, next) => {
  res.send(error);
});

app.listen(PORT, () => console.log('app listening on port', PORT));
