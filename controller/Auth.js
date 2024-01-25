const { User } = require("../model/User");
const crypto = require("crypto");
const { sanitizeUser } = require("../services/common");

const jwt = require("jsonwebtoken");

exports.createUser = async (req, res) => {
  try {
    const salt = crypto.randomBytes(16);
    crypto.pbkdf2(
      req.body.password,
      salt,
      310000,
      32,
      "sha256",
      async function (err, hashedPassword) {
        const user = new User({ ...req.body, password: hashedPassword, salt });
        const doc = await user.save();

        req.login(sanitizeUser(doc), (err) => {
          // this also calls serializer and adds to session
          if (err) {
            res.status(400).json(err);
          } else {
            const token = jwt.sign(
              sanitizeUser(doc),
              process.env.JWT_SECRET_KEY
            );
            res
              .cookie("jwt", token, {
                expires: new Date(Date.now() + 3600000),
                httpOnly: true,
              })
              .status(201)
              .json({ id: doc.id, role: doc.role });
          }
        });
      }
    );
  } catch (err) {
    res.status(400).json(err);
  }
};

exports.loginUser = async (req, res) => {
  try {
    const user = req.user;

    if (!user) {
      // User not found, handle accordingly
      return res.sendStatus(401);
    }

    const token = jwt.sign(sanitizeUser(user), process.env.JWT_SECRET_KEY);

    res
      .cookie("jwt", token, {
        expires: new Date(Date.now() + 3600000),
        httpOnly: true,
      })
      .status(200)
      .json({ id: user.id, role: user.role });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

exports.checkAuth = async (req, res) => {
  if (req.user) {
    res.json(req.user);
  } else {
    res.sendStatus(401);
  }
};
