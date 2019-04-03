// ================= DEPENDANCIES ================== //
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken')
// ================= IMPORTS ================== //
const db = require('./data/dbConfig.js');
// ================= USES ================== //
const server = express();
server.use(helmet());
server.use(express.json());
server.use(cors());
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
      if (bcrypt.compareSync(password, user.password)){
        const token = generateToken(user)
        res.status(200).json({ message: `Hello ${user.username}`, token })
      } else {
        res
          .status(401)
          .json({ message: 'Username or Password do not match out records' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

const generateToken = user => {
  const payload = {
    subject: user.username,
  }
  const secret = "this is secret"
  const options = {
    expiresIn: '1d'
  }
 return jwt.sign(payload, secret, options)
}

server.get('/api/user', restricted, (req, res) => {
  db('users')
    .then(users => {
      res.status(200).json(users);
    })
    .catch(err => res.send(err));
});

function restricted(req, res, next) {
  const token = req.headers.authorization;
  token
    ? jwt.verify(token, "this is secret", (err, decodedToken) => {
        err
          ? res.status(401).json({ message: 'Invalid Credentials' })
          :(next(), req.decodedJWT = decodedToken)
    })
    : res.status(401).json({ message: 'Please provide a token' })
}

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
