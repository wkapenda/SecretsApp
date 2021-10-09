//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose")
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate')
const FacebookStrategy = require('passport-facebook').Strategy;

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));

// app.use(express.static("public"));

app.use(session({
  secret: 'The Biggest Secret',
  resave: false,
  saveUninitialized: true
}))

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/peopleDB", {useNewUrlParser: true, useUnifiedTopology: true});
//Prevent deprecation warning
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: [String]

});

userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate);

// const secret = "Thisisourlittlesecret.";
// userSchema.plugin(encrypt, { secret: secret, encryptedFields: ["password"] });

const User = mongoose.model("User", userSchema);

// CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
passport.use(User.createStrategy());

// LOCAL serialize and deserialize
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

//GLOBAL serialize and deserialize (Includes LOCAL)
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" //Solve the google + deprecation problem (Github Solution)
},
function(accessToken, refreshToken, profile, cb) {

  console.log(profile.displayName)

  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));

passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID,
  clientSecret: process.env.FACEBOOK_APP_SECRET,
  callbackURL: "http://localhost:3000/auth/facebook/secrets"
},
function(accessToken, refreshToken, profile, done) {

  console.log(profile)
  User.findOrCreate( {facebookId: profile.id }, function(err, user) {

    if (err) { return done(err); }
    done(null, user);
  });
}
));



app.get("/", function(req, res){
  res.render("home");
});

app.get("/auth/google",
  //initiate authentication with Google
  passport.authenticate("google", { scope: ["email profile"] })
  
);

app.get("/auth/facebook",
  //initiate authentication with Google
  passport.authenticate("facebook", { scope: ["email public_profile"]})
  
);

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

app.get("/auth/facebook/secrets", 
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/secrets", function(req, res){
  if(req.isAuthenticated()){
    res.render("secrets");
  } else {
    res.redirect("/login")
  }

  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if(err) {
      console.log(err)
    }else {
      if(foundUsers){
        res.render("secrets", {usersWithSecrets: foundUsers})
      }
    }
  });
});

app.get("/submit", function(req, res){
  if(req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login")
  }
});

app.get("/logout", function(req, res){
  req.logout();
  res.redirect('/');
  
});

app.post("/submit", function(req, res){

  const submittedSecret = req.body.secret;


  User.findById(req.user.id, function(err, foundUser) {


    if (err) { 
      console.log(err);
      res.redirect("/submit")
     } else {
       if (foundUser) {
        //  foundUser.secret = submittedSecret;
        foundUser.secret.push(submittedSecret);
        console.log(foundUser.secret);
        foundUser.save(function(){
        res.redirect("/secrets")
         })
       }
     }
    });

});

app.post("/register", function(req, res){

  User.register({username: req.body.username,}, req.body.password, function(err, user) {
    if (err) { 
      console.log(err);
      res.redirect("/register")
     } else {
       passport.authenticate("local")(req, res, function(){
         res.redirect("/secrets")
       })
     }
    });

});


app.post("/login", function(req, res){

  console.log("Login")

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err) {
    if (err) { 
      console.log(err);
     } else {
        passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets")
      })
     }
  });

});
//


app.listen(3000, function() {
  console.log("Server started on port 3000");
});
