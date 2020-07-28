// jshint esversion:6
require('dotenv').config();
const express = require('express');
const bodyparser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose')
const app = express();

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyparser.urlencoded({
    extended: true
}));
app.use(session({
    secret: 'Our little secret',
    resave: false,
    saveUninitialized: false,
}));
app.use(passport.initialize());
app.use(passport.session());


mongoose.connect('mongodb://localhost:27017/userDB', {
    useNewUrlParser: true
});
mongoose.set('useCreateIndex', true);


const user = new mongoose.Schema({
    email: String,
    password: String
});
user.plugin(passportLocalMongoose);

// Models User
const User = new mongoose.model('User', user)

// Use Passport to 
passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// HOME
app.route('/')
    .get((req, res) => {
        res.render('home');
    })

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
            if(err){
                alert(err);
            } else {
                passport.authenticate('local')(req,res,() => {
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
        User.register({username: req.body.username}, req.body.password, (err,user) => {
            console.log(user);
            if(err){
                res.redirect('/register');
            } else {
                passport.authenticate('local')(req,res, () => {
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
        if(req.isAuthenticated()){
            res.render('secrets');
        } else {
            res.redirect('/login');
        }
    })



app.listen(3000, function () {
    console.log("Server started on port 3000");
});