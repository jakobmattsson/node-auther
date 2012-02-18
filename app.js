var sys = require('sys');
var assert = require('assert');
var async = require("async");
var autherCore = require('./auther.js');

var print = function() {
};

var auther = autherCore.createAuthenticator();


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
    auther.resetPassword('jakob1@gmail.com', 'token', 'new_password', function(err) {
      assert.equal(err, "Invalid token");
      callback();
    });
  },
  function(callback) {
    auther.generateToken('jakob1@gmail.com', function(err, token) {
      assert.ok(token);
      auther.resetPassword('jakob1@gmail.com', token, 'new_password', function(err) {
        assert.ifError(err);
        callback();
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
      auther.validateEmail('jakob8@gmail.com', activationToken, function(err, alreadyValidated) {
        assert.ifError(err);
        assert.equal(false, alreadyValidated);
        auther.validateEmail('jakob8@gmail.com', activationToken, function(err, alreadyValidated) {
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
  
  auther.print();
});


