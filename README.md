Node-auther
===========

What
----

A library for handling authentication.



Example usage
-------------

Below, `err` is the same for all callbacks; a string that describes the error, if any. Otherwise it's `null`.

If `err` is anything else than `null`, all other parameters are meaningless and should not be used.


````javascript
// Creates a new authenticator object with all settings set to default values.
var auth = auther.createAuthenticator();

// Tests if the given user exists.
auth.isUser('name@email.com', function(err, exists, confirmed) {
  // exists: true or false, depending on if the user exists.
  // confirmed: true or false, depending of if the user has confirmed his/her email address.
});

// Creates a new user, given an email and a password.
auth.createUser('name@email.com', 'summer', function(err, confirmationToken) {
  // confirmationToken: a string used to confirm the users email address.
});

// Deletes the given user.
auth.deleteUser('name@email.com', function(err, foundUser) {
  // foundUser: true if the user existed before this invocation. false if there was no user with the provided name.
});

// Authenticates a user, given the users email, password and a TTL (in minutes) for the authentication.
auth.authenticatePassword('name@email.com', 'password', 30, function(err, token) {
  // token: a token that can be used for authentication and resetting the given users password.
});

// Authenticates a user, given the authentication token.
auth.authenticateToken('0123456789abcdef', function(err) {
  // no parameters. unless there is an error, the authentication process was successful.
});

// Invalidates the given token.
auth.invalidateToken('0123456789abcdef', function(err) {
  // no parameters. unless there is an error, the invalidation process was successful.
});

// Confirm the given email using a confirmation token.
auth.validateEmail('0123456789abcdef', 'name@email.com', function(err, alreadyConfirmed) {
  // alreadyConfirmed: true or false, depending on if the email was already confirmed or not.
});

// Generates an authentication token for a particular user with a given TTL (in minutes).
auth.generateToken('name@email.com', 30, function(err, token) {
  // token: A token that can be used for authentication and resetting the given users password.
});

// Updates a users password, given a authentication token and a new password.
auth.updatePassword('0123456789abcdef', 'new_password', function(err) {
  // no parameters. unless there is an error, the update process was successful.
});
````


Creating more advanced authenticators
-------------------------------------

