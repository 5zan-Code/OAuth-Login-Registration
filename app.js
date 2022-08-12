const express = require('express')
const mongoose = require('mongoose')
const bodyParser = require('body-parser')
const ejs = require('ejs')
const colors = require('colors')
const dotenv = require('dotenv').config();
const session = require('express-session')
const passport = require('passport')
const LocalStrategy = require('passport-local')
const passportLocalMongoose = require('passport-local-mongoose')
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook')
const GitHubStrategy = require('passport-github2')
const findOrCreate = require('mongoose-findorcreate')
const bcrypt = require('bcrypt')
const saltRound = 10;

const app = express();

app.use(express.static('public'))
app.set('view engine', 'ejs')
app.use(bodyParser.urlencoded({extended: true}))


app.use(session({
    secret: process.env.SECRET_KEY,
    resave: false,
    saveUninitialized: false,

}));

app.use(passport.initialize());
app.use(passport.session());


mongoose.connect(process.env.DB_URL, {useNewUrlParser: true}, ()=> {
    console.log('DB Connected!'.bgCyan)
})

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    githubId: String,
    secret: String
}
)

// FB.getLoginStatus(function(response) {
//   statusChangeCallback(response);
// });

userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate)

const User = mongoose.model('User', userSchema)

passport.use(new LocalStrategy(User.authenticate()));

passport.serializeUser((user, done)=>{
  done(null, user.id)
})
passport.deserializeUser((id, done)=>{
  User.findById(id, (err, user)=>{
    done(err, user)
  })
})

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile.id)
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
    
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
  clientID: process.env.FB_APP_KEY,
  clientSecret: process.env.FB_APP_KEY_SECRET,
  callbackURL: "http://localhost:3000/auth/facebook/secrets"
},
function(accessToken, refreshToken, profile, cb) {
  console.log(profile.id)
  User.findOrCreate({username: profile.displayName,facebookId: profile.id }, function (err, user) {
    
    return cb(err, user);
  });
}
));

passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_KEY,
  clientSecret: process.env.GITHUB_KEY_SECRET,
  callbackURL: "http://localhost:3000/auth/github/secrets"
},
function(accessToken, refreshToken, profile, done) {
  User.findOrCreate({ username: profile.displayName,githubId: profile.id }, function (err, user) {
    return done(err, user);
  });
}
));

app.get('/', (req,res)=>{
    res.render('home')
    });

app.get('/login', (req,res)=>{
    res.render('login')
})


app.get('/register', (req,res)=>{
    res.render('register')
})
app.get('/secrets', (req,res)=>{
   User.find({"secrets": {$ne: null}}, (err, result)=>{
res.render('secrets', {results: result})
   })
})

app.get("/logout",(req, res)=>{

    req.logout((err)=> {
  
      if (err){
  
        console.log(err);
  
      } else{
        
        res.redirect("/");
  
      }
  
  
  
    });
  
  });

  app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

  app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });


  app.get('/auth/facebook',
  passport.authenticate('facebook', {scope: ['profile']}));

  app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

  app.get('/auth/github',
  passport.authenticate('github', { scope: [ 'user:email' ] }));

app.get('/auth/github/secrets', 
  passport.authenticate('github', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });
  app.get('/submit', (req, res)=>{
    if(req.isAuthenticated()){
      res.render('submit')
  }else{
      res.redirect('/login')
  }
  })

// *********************************** POST ROUTES *******************************************************

  app.post("/login", function(req, res){

    const user = new User({
      username: req.body.username,
      password: req.body.password
    });
    req.login(user, function(err){
      if (err) {
        console.log(err);
      } else {
        passport.authenticate("local")(req, res, function(){
           
          res.redirect("/secrets");
        });
      }
    });
  
  });

app.post('/register', (req,res)=> {    
    User.register({username: req.body.username}, req.body.password, (err, user)=>{
        if(err){
            console.log(err)
            res.redirect('/register')
        }else{
            passport.authenticate('local')(req,res, ()=>{
                res.redirect('/secrets')
            })
        }
    })
})


app.post('/submit', (req,res)=>{
   const secretText = req.body.secret;

   User.findById(req.user._id, (err, result)=> {
    if(err){
      console.log(err)
    }else{
      if(result) {
        result.secret = secretText
        result.save((err)=>{
          if(err){
            console.log(err)
          }else{
            res.redirect('/secrets')
          }
        })
      }
    }
   })
})


app.listen(process.env.PORT || 3000, ()=>{
    console.log(`Server is lit up at ${process.env.PORT}`.bgGreen);
})
