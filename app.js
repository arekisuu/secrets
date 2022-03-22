// Require NPM modules
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth2').Strategy;
const findOrCreate = require('mongoose-findorcreate');

// Set up NPM modules
const app = express();
app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended: true}));
app.set("view engine", "ejs");

// Set up session
app.use(session({
  secret: "p79TRd2WvR)$bzu",
  resave: false,
  saveUninitialized: false
}));

// Initialize passport.js
app.use(passport.initialize());
// Set passport.js to use session
app.use(passport.session());

// Connect node server to mongoDB database through mongoose
mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});

// Create a schema for new users
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

// Set up the above schema to use necessary plugins
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// Create a new mongoose model based on the aforementioned schema
const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// Handle serialization and deserialization through passport.js
passport.serializeUser((user, done) => {
  done(null, user.id);
});
passport.deserializeUser((id, done) => {
  User.findById(id, (err, user) => {
    done(err, user);
  })
});

// Create new strategy through passport.js to handle Google OAuth
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    passReqToCallback: true
  },
  function(request, accessToken, refreshToken, profile, done) {
    User.findOrCreate({
      googleId: profile.id
    }, function(err, user) {
      return done(err, user);
    });
  }
));

// Renders 'home' when a GET request is received on root route
app.get("/", (req, res) => {
  res.render("home");
});

// Sends an OAuth request to google when a GET request is received on /auth/google
app.get("/auth/google", passport.authenticate("google", {scope: ["email", "profile"]}));

// Authenticates users when a GET request is received on /auth/google/secrets and redirects them accordingly
app.get("/auth/google/secrets",
    passport.authenticate( "google", {
        successRedirect: "/secrets",
        failureRedirect: "/login"
}));

// Render 'login' when a GET request is received on /login route
app.get("/login", (req, res) => {
  res.render("login");
});

// Render 'register' when a GET request is received on /register route
app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/secrets", (req, res) => {
  // Find every user in the database that has a value in the "secret" field
  User.find({"secret": {$ne: null}}, (err, foundUsers) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        // Render 'secrets' passing the found users as an EJS variable
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

// End user session and redirects them to root route when a GET request is received on /logout
app.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

app.post("/register", (req, res) => {
  User.register({
    username: req.body.username
  }, req.body.password, (err, user) => {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login", (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  req.login(user, (err) => {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/submit", (req, res) => {
  User.findById(req.user.id, (err, foundUser) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = req.body.secret;
        foundUser.save(() => {
          res.redirect("/secrets");
        });
      }
    }
  });
});

// Listen on unspecified cloud port OR local port 3000 and logs on success
app.listen(process.env.PORT || 3000, () => {console.log("Server running.")});
