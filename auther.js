var jshashes = require('jshashes');
var rbytes = require('rbytes');




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





// TODO:
// * single user throttling
// * system wide throttling
// * garbage collecting tokens
// * two build-in persisters; one inmemory and one connecting to a central service.
// * sending emails

// Notes:
// * The activation token is not guaranteed to be unique. It's just an identifier for each user.





exports.createAuthenticator = function(config) {
  config = config || {};
  config.badPasswords = config.badPasswords || ['password', '123456'];
  config.minPasswordLength = config.minPasswordLength || 4;

  var storage = config.storage;

  var validatePassword = function(password, callback) {
    if (password.length < config.minPasswordLength) {
      callback("Password too short");
      return;
    }

    if (config.badPasswords.indexOf(password) !== -1) {
      callback('Password too common');
      return;
    }

    callback();
  };
  var makeUniqueToken = function(callback) {
    var token = createSalt();
    storage.isTokenUnique(token, function(err, uniq) {
      if (err) {
        callback(err);
        return;
      }
      if (uniq) {
        callback(null, token);
      } else {
        makeUniqueToken(callback);
      }
    });
  };


  var auth = {};

  // Generate a token that can be used to reset password or login
  auth.generateToken = function(email, expiry, callback) {
    if (isUndefined(callback)) {
      callback = expiry;
      expiry = 60;
    }
    
    makeUniqueToken(function(err, token) {
      if (err) {
        callback('Internal error');
        return;
      }

      storage.putToken(hash(token), email, getTime() + expiry, function(err) {
        if (err) {
          callback('Internal error');
          return;
        }
        callback(null, token);
      });
    });
  };



  auth.updatePassword = function(token, password, callback) {
    validatePassword(password, function(err) {
      if (err) {
        callback(err);
        return;
      }

      storage.getTokenData(hash(token), function(err, expiry, email) {
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
    });
  };

  // callback(err, alreadyValidated)
  auth.validateEmail = function(token, email, callback) {
    storage.getUser(email, function(err, user) {
      if (err) {
        callback("Invalid user");
        return;
      }

      if (!user.activationToken) {
        callback(null, true);
        return;
      }

      if (hash(token) == user.activationToken) {
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

      validatePassword(password, function(err) {
        if (err) {
          callback(err);
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
    storage.getTokenData(hash(authToken), function(err, expiry) {
      if (err || expiry < getTime()) {
        callback("Invalid token");
      } else {
        callback();
      }
    });
  };

  // callback(err)
  auth.invalidateToken = function(authToken, callback) {
    storage.putToken(hash(authToken), null, 0, function(err) {
      callback(err);
    });
  };


  return auth;
};



