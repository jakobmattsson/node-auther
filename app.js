var sys = require('sys');
var assert = require('assert');
var async = require("async");
var autherCore = require('./auther.js');

var block = function(f) {
  return f();
};

var storage = block(function() {
  var db = {
    users: {},
    tokens: {}
  };

  return {
    putToken: function(token, email, expires, callback) {
      db.tokens[token] = { email: email, expires: expires };
      callback();
    },
    isTokenUnique: function(token, callback) {
      callback(null, !db.tokens[token]);
    },
    getTokenData: function(token, callback) {
      if (!db.tokens[token]) {
        callback("Invalid token");
      } else {
        callback(null, db.tokens[token].expires, db.tokens[token].email);
      }
    },

    deleteExpiredTokens: function(threshold, callback) {
      
      
    },

    setUserConfirmed: function(email, callback) {
      if (!db.users[email]) {
        callback('Invalid user');
      } else {
        db.users[email].activationToken = null;
        callback();
      }
    },

    setUserPassword: function(email, password, callback) {
      if (!db.users[email]) {
        callback('Invalid user');
      } else {
        db.users[email].password = password;
        callback();
      }
    },

    createUser: function(email, data, callback) {
      var newuser = false;
      var user = db.users[email];

      if (!user) {
        newuser = true;
        user = db.users[email] = {};
      }

      Object.keys(data).forEach(function(key) {
        user[key] = data[key];
      });

      callback(null, newuser);
    },
    getUser: function(email, callback) {
      callback(null, db.users[email]);
    },
    delUser: function(email, callback) {
      if (db.users[email]) {
        delete db.users[email];
        callback(null, true);
      }
      callback(null, false);
    },
    print: function() {
      console.log(require('sys').inspect(db, false, 10));
    }
  };
});

var auther = autherCore.createAuthenticator({ storage: storage });




async.series([
  function(callback) {
    auther.createUser('jakob1@gmail.com', 'test', callback);
  },
  function(callback) {
    auther.createUser('jakob2@gmail.com', 'testar', callback);
  },
  function(callback) {
    auther.createUser('jakob3@gmail.com', 'a', function(err) {
      assert.equal(err, 'Password too short');
      callback();
    });
  },
  function(callback) {
    auther.createUser('jakob4@gmail.com', '123456', function(err) {
      assert.equal(err, 'Password too common');
      callback();
    });
  },
  function(callback) {
    auther.createUser('jakob2@gmail.com', 'testar', function(err) {
      assert.equal(err, "Email already taken");
      callback();
    });
  },
  function(callback) {
    auther.createUser('not_an_email', 'testar', function(err) {
      assert.equal(err, "Invalid email");
      callback();
    });
  },
  function(callback) {
    auther.authenticatePassword('jakob2@gmail.com', 'test', function(err) {
      assert.equal(err, "Invalid username or password");
      callback();
    });
  },
  function(callback) {
    auther.authenticatePassword('jakob1@gmail.com', 'test', function(err, token) {
      assert.ok(token);
      auther.authenticateToken(token, function(err) {
        assert.ifError(err);
        auther.invalidateToken(token, function(err) {
          assert.ifError(err);
          auther.authenticateToken(token, function(err) {
            assert.equal(err, "Invalid token");
            callback();
          });
        });
      });
    });
  },
  function(callback) {
    auther.updatePassword('token', 'new_password', function(err) {
      assert.equal(err, "Invalid token");
      callback();
    });
  },
  function(callback) {
    auther.generateToken('jakob1@gmail.com', function(err, token) {
      assert.ok(token);
      auther.updatePassword(token, '12', function(err) {
        assert.equal(err, 'Password too short');
        auther.updatePassword(token, 'new_password', function(err) {
          assert.ifError(err);
          callback();
        });
      });
    });
  },
  function(callback) {
    auther.authenticatePassword('jakob1@gmail.com', 'test', function(err, token) {
      assert.equal(err, "Invalid username or password");
      callback();
    });
  },
  function(callback) {
    auther.authenticatePassword('jakob1@gmail.com', 'new_password', function(err, token) {
      assert.ifError(err);
      callback();
    });
  },
  function(callback) {
    auther.isUser('jakob1@gmail.com', function(err, isUser, isActivated) {
      assert.ifError(err);
      assert.ok(isUser);
      assert.equal(false, isActivated);
      callback();
    });
  },
  function(callback) {
    auther.createUser('jakob8@gmail.com', 'lösenord', function(err, activationToken) {
      assert.ifError(err);
      assert.ok(activationToken);
      auther.validateEmail(activationToken, 'jakob8@gmail.com', function(err, alreadyValidated) {
        assert.ifError(err);
        assert.equal(false, alreadyValidated);
        auther.validateEmail(activationToken, 'jakob8@gmail.com', function(err, alreadyValidated) {
          assert.ifError(err);
          assert.equal(true, alreadyValidated);
          callback();
        });
      });
    });
  },
  function(callback) {
    auther.isUser('jakob8@gmail.com', function(err, isUser, isActivated) {
      assert.ifError(err);
      assert.ok(isUser);
      assert.ok(isActivated);
      callback();
    });
  }







  
  
  
  
], function(err) {
  if (err) {
    console.log("err", err);
  } else {
    console.log("done without errors!");
  }
  
  storage.print();
});


