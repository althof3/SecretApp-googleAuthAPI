// jshint esversion:6
require('dotenv').config();
const express = require('express');
const bodyparser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose')
const GoogleStrategy = require('passport-google-oauth2').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

// Static file in public folder
app.use(express.static('public'));

// allow .ejs to html templating
app.set('view engine', 'ejs');

// req.body.name
app.use(bodyparser.urlencoded({
    extended: true
}));

// SESSION
app.use(session({
    secret: 'Our little secret',
    resave: false,
    saveUninitialized: false,
}));
app.use(passport.initialize());
app.use(passport.session());

// server MongoDB
mongoose.connect('mongodb://localhost:27017/userDB', {
    useNewUrlParser: true
});
mongoose.set('useCreateIndex', true);

// scheme
const user = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String
});

// scheme PLUGIN
user.plugin(passportLocalMongoose);
user.plugin(findOrCreate);

// Models User
const User = new mongoose.model('User', user)

// Use Passport
passport.use(User.createStrategy());
passport.serializeUser((user,done) => {
    done(null, user.id)
});
passport.deserializeUser((id,done) => {
    User.findById(id, (err,user) => {
        done(err,user);
    })
});

// Google Auth
passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "http://127.0.0.1:3000/auth/google/secrets",
        passReqToCallback   : true
    },
    function (request, accessToken, refreshToken, profile, done) {
        User.findOrCreate({
            googleId: profile.id
        }, function (err, user) {
            return done(err, user);
        });
    }
));

// HOME
app.route('/')
    .get((req, res) => {
        res.render('home');
    })

// GOOGLE login
app.get('/auth/google',
    passport.authenticate('google', {
        scope: [ 'https://www.googleapis.com/auth/userinfo.profile',
      , 'https://www.googleapis.com/auth/userinfo.email' ]
    }));

app.get('/auth/google/secrets',
    passport.authenticate('google', {
        successRedirect: '/secrets',
        failureRedirect: '/login'
    }));

// LOGIN
app.route('/login')
    .get((req, res) => {
        res.render('login');
    })
    .post((req, res) => {

        const user = new User({
            username: req.body.username,
            password: req.body.password
        });

        req.logIn(user, (err) => {
            if (err) {
                alert(err);
            } else {
                passport.authenticate('local')(req, res, () => {
                    res.redirect('/secrets');
                });
            }
        })
    })

// REGISTER
app.route('/register')
    .get((req, res) => {
        res.render('register');
    })
    .post((req, res) => {
        User.register({
            username: req.body.username
        }, req.body.password, (err, user) => {
            console.log(user);
            if (err) {
                res.redirect('/register');
            } else {
                passport.authenticate('local')(req, res, () => {
                    res.redirect('/secrets');
                });
            }
        });
    })

// LOGOUT
app.route('/logout')
    .get((req, res) => {
        req.logOut();
        res.redirect('/')
    })

// SECRETS
app.route('/secrets')
    .get((req, res) => {
        if (req.isAuthenticated()) {
            res.render('secrets');
        } else {
            res.redirect('/login');
        }
    })



app.listen(3000, function () {
    console.log("Server started on port 3000");
});