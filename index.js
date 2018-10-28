const express = require('express');
const compression = require('compression');
const session = require('express-session');
const mongoose = require('mongoose');
const dotenv = require('dotenv').config();
const chalk = require('chalk');
const lusca = require('lusca');
const MongoStore = require('connect-mongo')(session);
const flash = require('express-flash');
const path = require('path');
const sass = require('node-sass-middleware');

const app = express();
const port = process.env.PORT;


/**
 * Controllers (route handlers).
 */
const authController = require('./controllers/auth');

mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true });
mongoose.connection.on('error', (err) => {
    console.error(err);
    console.log('%s MongoDB connection error. Please make sure MongoDB is running.', chalk.red('✗'));
    process.exit();
});

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');
app.use(express.static(path.join(__dirname, 'public')))
app.use(session({
    resave: true,
    saveUninitialized: true,
    secret: process.env.SESSION_SECRET,
    cookie: { maxAge: 1209600000 }, // two weeks in milliseconds
    store: new MongoStore({
        url: process.env.MONGODB_URI,
        autoReconnect: true,
    })
}));
app.use((req, res, next) => {
    if (req.path === '/api/upload') {
        next();
    } else {
        lusca.csrf()(req, res, next);
    }
});
app.use(lusca.xframe('SAMEORIGIN'));
app.use(lusca.xssProtection(true));


app.get('/login', authController.getLogin);
app.get('/register', authController.getRegister);
app.get('/forgot-password', authController.forgotPassword);

app.listen(port, ()=>`Server is running on port ${port}!`);