require('dotenv').config();
const express = require('express');
const cookieSession = require('cookie-session');
const path = require('path');
var bodyParser = require('body-parser');
var helmet = require('helmet');
var xssClean = require('xss-clean');
var cors = require('cors');
var { encrypt, decrypt } = require('./util/crypto');

const app = express();
const port = process.env.PORT || 1000;
var pass;


// Middlewares
app.use(
    helmet({
      contentSecurityPolicy: false,
    })
  );
// app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieSession({
    name: process.env.COOKIE_NAME,
    secret: process.env.COOKIE_SECRET,
    httpOnly: true,
    sameSite: true,
    secure: process.env.SECURE_COOKIE == 1? true : false
}));
app.use(express.json());
app.use(xssClean());

// set the view engine to ejs
app.set('view engine', 'ejs');

// Endpoints
app.get('/generate-passcode-a', (req, res) => {
    res.render('pages/index', { passcode: pass });
});
app.get('/enter-passcode', (req, res) => {
    const redirectUrl = getParameterByName('url', req.originalUrl);
    const other = getParameterByName('other', req.originalUrl);
    res.render('pages/enter-passcode', { redirectUrl: redirectUrl, other: other, success: '', error: '' });
});
app.post('/submit-passcode', (req, res) => {
    let errorMessage = '';

    if(!req.body.passcode)
        errorMessage = 'Please Provide Passcode!';
    else if(isNaN(req.body.passcode))
        errorMessage = 'Please must be a Number!';
    else if(req.body.passcode.toString().length > 5 || req.body.passcode.toString().length < 5)
        errorMessage = 'Passcode must be of 5 digits!';

    if(errorMessage) {
        res.render('pages/enter-passcode', { redirectUrl: req.body.redirectUrl, other: req.body.other, success: '', error: errorMessage });
        return;
    }


    if (parseInt(req.body.passcode) == pass) {
        let expiryDateTime = getExpiryDateTime();
        req.session.ref = expiryDateTime.getTime().toString();
        req.sessionOptions.expires = expiryDateTime;
        let decryptedUrl = req.body.redirectUrl && req.body.other ? 
            decrypt({ encryptedData: req.body.redirectUrl, iv: req.body.other }) : null;

        if(decryptedUrl){
            res.redirect(decryptedUrl);
        } else {
            res.render('pages/enter-passcode', { redirectUrl: req.body.redirectUrl, other: req.body.other, success: 'Validation Successful!', error: '' });
        }
    } else {
        res.render('pages/enter-passcode', { redirectUrl: req.body.redirectUrl, other: req.body.other, success: '', error: 'Invalid Passcode!' });
    }
});

// Serve Static Files
app.use(function(req, res, next){
    validate(req, res, next, true);
}, express.static(path.join(__dirname, 'public')));

// 404
app.use(function(req, res, next){
    res.render('pages/404');
});



// Generate password
function generateRandomNumber() {
    pass = Math.floor(Math.random() * 90000) + 10000;
}
// Get Incremental time w.r.t defined session expiry hours
function getExpiryDateTime() {
    let dateTime = new Date();
    dateTime.setHours(dateTime.getHours() + parseInt(process.env.SESSION_EXPIRY_HOURS));
    return dateTime;
}
// Validation for every route
function validate(req, res, next, flag = false) {
    var fullUrl = req.protocol + '://' + req.get('host') + req.originalUrl;
    var encrypted = encrypt(fullUrl);

    if(req.originalUrl == '/'){
        next();
    } else if (req && req.session && req.session.ref) {
        var expiryTimeFromCookie = isNaN(req.session.ref) ? null : parseInt(req.session.ref);
        var currentDatetime = new Date().getTime();

        if (!expiryTimeFromCookie) {
            res.redirect('/enter-passcode?url=' + encrypted.encryptedData + '&other=' + encrypted.iv); // activate your session
        } else if (expiryTimeFromCookie <= currentDatetime) {
            res.redirect('/enter-passcode?url=' + encrypted.encryptedData + '&other=' + encrypted.iv); // reactivate your session
        } else {
            // Session Valid.
            // if (req.originalUrl == 'enter-passcode' && req.params.url) {
            //     flag ? next() : res.redirect(req.params.url);
            // } else {
            //     console.log("B")
            //     if (fullUrl) {
            //         flag ? next() : res.redirect(fullUrl);
            //     }
            // }
            next();
        }
    } else {
        res.clearCookie("ref");
        res.redirect('/enter-passcode?url=' + encrypted.encryptedData + '&other=' + encrypted.iv);
    }
}
// Extract Query String Parameter
function getParameterByName(name, url) {
    name = name.replace(/[\[\]]/g, '\\$&');
    var regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)'),
        results = regex.exec(url);
    if (!results) return null;
    if (!results[2]) return '';
    return decodeURIComponent(results[2].replace(/\+/g, ' '));
}


// Starting Application
app.listen(port, () => {
    console.log(`Server started at port ${port}`);
    generateRandomNumber();
    setInterval(generateRandomNumber, process.env.PASSCODE_RENEWAL_TIMEOUT * 60 * 1000); // *60 - SECONDS IN A MINUTE : *1000 MILISECONDS IN A SECOND
});