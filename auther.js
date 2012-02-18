var jshashes = require('jshashes');
var rbytes = require("rbytes");




var block = function(f) {
  return f();
};
var hash = function(str) {
  return new jshashes.SHA256().hex(str);
};
var createSalt = function() {
  return rbytes.randomBytes(32).toHex();
};
var getTime = function() {
  return new Date().getTime();
};
var isUndefined = function(x) {
  return typeof x == 'undefined';
};


var storage = block(function() {
  var all = {
    db: {},
    tokens: {}
  };

  var db = all.db;
  var tokens = all.tokens;
  return {
    putToken: function(token, expires, callback) {
      tokens[token] = expires;
      callback();
    },
    getTokenExpiry: function(token, callback) {
      if (!tokens[token]) {
        callback("Invalid token");
      } else {
        callback(null, tokens[token]);
      }
    },
    putUser: function(email, data, callback) {
      var newuser = false;
      var user = db[email];

      if (!user) {
        newuser = true;
        user = db[email] = {};
      }

      Object.keys(data).forEach(function(key) {
        user[key] = data[key];
      });

      callback(null, newuser);
    },
    getUser: function(email, callback) {
      callback(null, db[email]);
    },
    delUser: function(email, callback) {
      if (db[email]) {
        delete db[email];
        callback(null, true);
      }
      callback(null, false);
    },
    all: function() {
      return all;
    }
  };
});



// TODO:
// * single user throttling
// * system wide throttling
// * guaranteed token uniqueness







exports.createAuthenticator = function(config) {
  config = config || {};
  config.badPasswords = config.badPasswords || ['password', '123456'];



  var auth = {};

  auth.generateToken = function(email, expiry, callback) {
    if (isUndefined(callback)) {
      callback = expiry;
      expiry = 60;
    }

    var token = createSalt();

    storage.putToken(hash(token), getTime() + expiry, function(err) {
      if (err) {
        callback('Internal error');
        return;
      }
      callback(null, token);
    });
  };



  auth.resetPassword = function(email, resetToken, password, callback) {

    // kontrollera att det är ett bra lösenord, som vanligt.

    storage.getTokenExpiry(hash(resetToken), function(err, expiry) {
      if (err || expiry < getTime()) {
        callback("Invalid token");
        return;
      }

      storage.getUser(email, function(err, user) {
        if (err) {
          callback("Internal error");
          return;
        }

        storage.putUser(email, {
          password: hash(password + user.salt)
        }, function(err) {
          if (err) {
            callback("Internal error");
          } else {
            callback();
          }
        });
      });
    });
  };

  // callback(err, alreadyValidated)
  auth.validateEmail = function(email, validationToken, callback) {
    storage.getUser(email, function(err, user) {
      if (err) {
        callback("Invalid user");
        return;
      }

      if (!user.activationToken) {
        callback(null, true);
        return;
      }

      if (hash(validationToken) == user.activationToken) {
        storage.putUser(email, { activationToken: null }, function(err) {
          callback(err, false);
        });
      } else {
        callback("Invalid token");
        return;
      }
    });
  };



  // callback(err, isUser, isActivated)
  auth.isUser = function(email, callback) {
    storage.getUser(email, function(err, user) {
      if (err) {
        callback(err);
      } else {
        callback(null, !!user, user && !user.activationToken);
      }
    });
  };

  // callback(err)
  auth.createUser = function(email, password, callback) {
    if (email.indexOf('@') === -1) {
      callback('Invalid email');
      return;
    }

    storage.getUser(email, function(err, user) {
      if (err || user) {
        callback('Email already taken');
        return;
      }

      if (password.length <= 3) {
        callback("Password too short");
        return;
      }

      if (config.badPasswords.indexOf(password) !== -1) {
        callback('Password too common');
        return;
      }

      var salt = createSalt();
      var activationToken = createSalt();

      storage.putUser(email, {
        password: hash(password + salt),
        activationToken: hash(activationToken),
        salt: salt
      }, function(err) {
        if (err) {
          callback(err);
          return;
        }

        callback(null, activationToken);
      });
    });
  };

  // callback(err, deletedAnActualUser)
  auth.deleteUser = function(email, callback) {
    storage.delUser(email, function(err, deletedAnActualUser) {
      callback(err, deletedAnActualUser);
    });
  };



  // callback(err, authToken)
  auth.authenticatePassword = function(email, password, sessionLength, callback) {
    if (typeof callback == "undefined") {
      callback = sessionLength;
      sessionLength = 30;
    }

    storage.getUser(email, function(err, user) {
      if (err || !user || hash(password + user.salt) != user.password) {
        callback('Invalid username or password');
        return;
      }

      auth.generateToken(email, sessionLength, callback);
    });
  };


  // callback(err)
  auth.authenticateToken = function(authToken, callback) {
    storage.getTokenExpiry(hash(authToken), function(err, expiry) {
      if (err || expiry < getTime()) {
        callback("Invalid token");
      } else {
        callback();
      }
    });
  };

  // callback(err)
  auth.invalidateToken = function(authToken, callback) {
    storage.putToken(hash(authToken), 0, function(err) {
      callback(err);
    });
  };




  auth.print = function() {
    console.log(require('sys').inspect(storage.all(), false, 10));
  };

  
  return auth;
};


