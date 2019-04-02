// ================= DEPENDANCIES ================== //
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const KnexSessionStore = require('connect-session-knex')(session)
// ================= IMPORTS ================== //
const db = require('./data/dbConfig.js');
// =========SESSIONS AND COOKIES CONFIG======= //
const sessionConfig = {
  name: 'theme',
  secret: 'this should actually be a envoirment variable to be used as encryptionkey',
  cookie:{
    maxAge: 100 * 60 * 60,
    secure: false, // this makes it so that only HTTPS uses the cookie
    httpOnly:true 
  },
  resave:false, // do not recreate new session
  saveUnititalized: false, // GDPR
  store: new KnexSessionStore({
    knex: db,
    tablename: 'sessions',
    sidfeildname: 'sid',
    createtable: true,
    clearInterval: 1000 * 60 * 30
  })
}
// ================= USES ================== //
const server = express();
server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session(sessionConfig));
// ================= ENDPOINTS ================== //
server.get('/', (req, res) => {
  res.send('Server is active.');
});

server.post('/api/register', (req, res) => {
  let { username, password } = req.body;

  req.body.password = bcrypt.hashSync(password, 10);

  db('users')
    .insert(req.body)
    .then(ids => {
      const id = ids[0];
      db('users')
        .where({ id })
        .first()
        .then(user => {
          res.status(200).json(user);
        });
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  db('users')
    .where({ username })
    .first()
    .then(user => {
      bcrypt.compareSync(password, user.password)
        ? req.session.user = user && res.status(200).json({ message: `Hello ${user.username}` })
        : res
          .status(401)
          .json({ message: 'Username or Password do not match out records' });
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.get('/api/user', restricted, (req, res) => {
  db('users')
    .then(users => {
      res.status(200).json(users);
    })
    .catch(err => res.send(err));
});

function restricted(req, res, next) {
  req.session && req.session.user 
    ? next() 
    : res.status(401).json({ message: 'Invalid Credentials' })
}

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
