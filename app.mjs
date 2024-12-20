import express from 'express';
import session from 'express-session';
import pg from 'pg';
import connectPgSimple from 'connect-pg-simple';
import passport from 'passport';
import local from 'passport-local';
import bcryptjs from 'bcryptjs';
import cookieParser from 'cookie-parser';
import flash from 'connect-flash';
import 'dotenv/config';

const app = express();

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));

const pool = new pg.Pool({
  connectionString: process.env.DB,
});

const expressSessionPgStore = new connectPgSimple(session);

app.use(
  session({
    store: new expressSessionPgStore({
      pool,
    }),
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
  }),
);

passport.use(
  new local.Strategy(async (username, password, done) => {
    try {
      // Check user input matches database users table.
      const { rows } = await pool.query(
        'SELECT * FROM users WHERE username = $1',
        [username],
      );
      const user = rows[0];

      if (!user) {
        return done(null, false, {
          type: 'login',
          message: 'That username does not exist',
        });
      }

      const match = await bcryptjs.compare(password, user.password);
      if (!match) {
        return done(null, false, {
          type: 'login',
          message: 'The password entered is incorrect',
        });
      }

      return done(null, user);
    } catch (error) {
      return done(error);
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
  } catch (error) {
    done(error);
  }
});

app.use(passport.session());
app.use(cookieParser(process.env.SECRET));
app.use(flash());

// Debug middleware.
app.use((req, res, next) => {
  console.log('sesh:', req.session);
  console.log('user:', req.user);
  next();
});

app.get('/', (req, res, next) => {
  res.render('index', {
    title: 'Some Web App',
    user: req.user,
    messages: req.flash('login'),
  });
});

app.get('/sign-up', (req, res, next) => {
  res.render('sign-up-form', { title: 'Sign Up', user: req.user });
});

app.post('/sign-up', async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcryptjs.hash(password, 10);
    await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [
      username,
      hashedPassword,
    ]);
    res.status(303).redirect('/');
  } catch (error) {
    next(error);
  }
});

app.post(
  '/log-in',
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/',
    failureFlash: true,
  }),
);

app.post('/log-out', (req, res, next) => {
  req.logOut((error) => {
    if (error) return next(error);
    res.status(303).redirect('/');
  });
});

app.use((req, res, next) => {
  next(new Error('404: That page does not exist'));
});

app.use((error, req, res, next) => {
  res.render('error', { title: 'Error', error });
});

app.listen(process.env.PORT, () =>
  console.log('app listening on port', process.env.PORT),
);
