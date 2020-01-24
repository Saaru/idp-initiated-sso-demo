var ejs = require('ejs');
var fs = require('fs');
var path = require('path');
var express = require("express");
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var passport = require('passport');
var saml = require('passport-saml');
const { MetadataReader, toPassportConfig } = require('passport-saml-metadata');

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

const reader = new MetadataReader(fs.readFileSync(path.join(__dirname, './allbound_metadata.xml'), 'utf8'));
const config = toPassportConfig(reader);

fs.writeFile(path.join(__dirname, '/idp_cert.pem'), config.cert, function(err) {
  if(err) {
      return console.log(err);
  }
  console.log("The file was saved!");
}); 

var samlStrategy = new saml.Strategy({
  // URL that goes from the Identity Provider -> Service Provider
  callbackUrl: "http://localhost:9090/login/callback",
  // URL that goes from the Service Provider -> Identity Provider
  entryPoint: config.entryPoint,
  issuer: config.identityProviderUrl,
  identifierFormat: null,
  // Identity Provider's public key
  cert: fs.readFileSync(__dirname + '/idp_cert.pem', 'utf8'),
  validateInResponseTo: false,
  disableRequestedAuthnContext: true
}, function(profile, done) {
  return done(null, profile); 
});

passport.use(samlStrategy);

var app = express();

app.use(cookieParser());
app.use(bodyParser());
app.use(session({secret: "secret"}));
app.use(passport.initialize());
app.use(passport.session());
app.set('view engine', 'ejs');

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated())
    return next();
  else
    return res.redirect('/login/fail');
}

app.get('/',
  ensureAuthenticated, 
  function(req, res) {
    res.render('index', { user: req.user});
    console.log(req.user);
  }
);

app.post('/login/callback',
   passport.authenticate('saml', { failureRedirect: '/login/fail' }),
  function(req, res) {
    res.redirect('/');
  }
);

app.get('/login/fail', 
  function(req, res) {
    res.status(401).send('Login failed');
  }
);

//general error handler
app.use(function(err, req, res, next) {
  console.log("Fatal error: " + JSON.stringify(err));
  next(err);
});

var server = app.listen(9090, function () {
  console.log('Listening on port %d', server.address().port)
});
