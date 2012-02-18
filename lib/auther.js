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


// * two build-in persisters; one inmemory and one connecting to a central service.
// * sending emails


exports.createAuthenticator = function(config) {
  config = config || {};
  config.badPasswords = config.badPasswords || ['password', '123456789'];
  config.minPasswordLength = config.minPasswordLength || 6;
  config.tokenGarbageCollectionInterval = config.tokenGarbageCollectionInterval || 30;
  var binding = config.storage;

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
  var makeUniqueToken = function(attempts, callback) {
    if (isUndefined(callback)) {
      callback = attempts;
      attempts = 10;
    }

    if (!attempts) {
      callback('Failed to generate unique token');
      return;
    }

    var token = createSalt();
    binding.getToken(token, function(err) {
      if (err) {
        callback(null, token);
      } else {
        makeUniqueToken(attempts - 1, callback);
      }
    });
  };
  var tokenGC = block(function() {
    var lastGC = 0;
    return function(f) {
      return function() {
        var self = this;
        var args = arguments
        var currentTime = getTime();

        if (lastGC + config.tokenGarbageCollectionInterval * 60 * 1000 <= currentTime) {
          lastGC = currentTime;
          binding.deleteExpiredTokens(currentTime, function() {
            f.apply(self, args);
          });
        } else {
          f.apply(self, args);
        }
      };
    };
  });

  var auth = {};

  auth.generateToken = tokenGC(function(email, expiry, callback) {
    if (isUndefined(callback)) {
      callback = expiry;
      expiry = 60;
    }
    
    makeUniqueToken(function(err, token) {
      if (err) {
        callback('Internal error');
        return;
      }

      binding.createToken(hash(token), email, getTime() + expiry * 60 * 1000, function(err) {
        if (err) {
          callback('Internal error');
          return;
        }
        callback(null, token);
      });
    });
  });
  auth.updatePassword = tokenGC(function(token, password, callback) {
    validatePassword(password, function(err) {
      if (err) {
        callback(err);
        return;
      }

      binding.getToken(hash(token), function(err, t) {
        if (err || t.expires < getTime()) {
          callback("Invalid token");
          return;
        }

        binding.getUser(t.email, function(err, user) {
          if (err) {
            callback("Internal error");
            return;
          }

          binding.setUserPassword(t.email, hash(password + user.salt), function(err) {
            if (err) {
              callback("Internal error");
            } else {
              callback();
            }
          });
        });
      });
    });
  });
  auth.confirmEmail = tokenGC(function(token, email, callback) {
    binding.getUser(email, function(err, user) {
      if (err) {
        callback("Invalid user");
        return;
      }

      if (!user.confirmationToken) {
        callback(null, true);
        return;
      }

      if (hash(token) == user.confirmationToken) {
        binding.setUserConfirmed(email, function(err) {
          callback(err, false);
        });
      } else {
        callback("Invalid token");
        return;
      }
    });
  });

  auth.isUser = tokenGC(function(email, callback) {
    binding.getUser(email, function(err, user) {
      callback(err, !err && !!user, !err && user && !user.confirmationToken);
    });
  });
  auth.createUser = tokenGC(function(email, password, callback) {
    if (email.indexOf('@') === -1) {
      callback('Invalid email');
      return;
    }

    binding.getUser(email, function(err, user) {
      if (!err) {
        callback('Email already taken');
        return;
      }

      validatePassword(password, function(err) {
        if (err) {
          callback(err);
          return;
        }

        var salt = createSalt();
        var confirmationToken = createSalt();

        binding.createUser(email, hash(password + salt), hash(confirmationToken), salt, function(err) {
          if (err) {
            callback(err);
            return;
          }

          callback(null, confirmationToken);
        });
      });
    });
  });

  auth.authenticatePassword = tokenGC(function(email, password, sessionLength, callback) {
    if (typeof callback == "undefined") {
      callback = sessionLength;
      sessionLength = 30;
    }

    binding.getUser(email, function(err, user) {
      if (err || !user || hash(password + user.salt) != user.password) {
        callback('Invalid username or password');
        return;
      }

      auth.generateToken(email, sessionLength, callback);
    });
  });
  auth.authenticateToken = tokenGC(function(authToken, callback) {
    binding.getToken(hash(authToken), function(err, t) {
      if (err || t.expires < getTime()) {
        callback("Invalid token");
      } else {
        callback();
      }
    });
  });
  auth.invalidateToken = tokenGC(function(authToken, callback) {
    binding.createToken(hash(authToken), null, 0, function(err) {
      callback(err);
    });
  });

  return auth;
};



