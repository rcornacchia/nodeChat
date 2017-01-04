const express = require('express'),
      app = express(),
      bodyParser = require('body-parser');
      logger = require('morgan'),
      config = require('./config/main'),
      mongoose = require('mongoose'),
      router = require('./router');

// connect mongoose to mongodb
mongoose.connect(config.database);

// start server
const server = app.listen(config.port);
console.log('Server started on port ' + config.port);

// enable logging
app.use(logger('dev'));

// enable body parsing
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Enable CORS from client-side
app.use(function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header('Access-Control-Allow-Methods', 'PUT, GET, POST, DELETE, OPTIONS');
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization, Access-Control-Allow-Credentials");
    res.header("Access-Control-Allow-Credentials", "true");
    next();
});

router(app);
