const passport = require("passport");

exports.isAuth = (req, res, done) => {
  return passport.authenticate("jwt");
};

exports.sanitizeUser = (user) => {
  return { id: user.id, role: user.role };
};
exports.cookieExtractor = function (req) {
  let token = null;
  if (req && req.cookies) {
    token = req.cookies["jwt"];
  }
  // TODO : this is temporary token for testing without cookie
  // token =
  //   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY1YWE3ZjFkNDVmOWQyYmY2YzhhNGVkYyIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzA1NjcyNDc4fQ.CaAGTdq-QfAWuaXtoTsrHlFj2deT_5ycOyQ09jFwJ1I";

  return token;
};
