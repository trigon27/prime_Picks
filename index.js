const express = require("express");
const server = express();
const mongoose = require("mongoose");
require("dotenv").config();

const { createProduct } = require("./controller/Product");
const productsRouter = require("./routes/Products");
const brandsRouter = require("./routes/Brand");
const categoryRouter = require("./routes/Categories");
const UserRouter = require("./routes/User");
const AuthRouter = require("./routes/Auth");
const CartRouter = require("./routes/Cart");
const OrderRouter = require("./routes/Order");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const JwtStrategy = require("passport-jwt").Strategy;
const cookieParser = require("cookie-parser");
const cors = require("cors");
const session = require("express-session");
const passport = require("passport");
const path = require("path");
const { User } = require("./model/User");
const { isAuth, sanitizeUser, cookieExtractor } = require("./services/common");
const LocalStrategy = require("passport-local").Strategy;

// Webhook;

// TODO: we will capture actual order after deploying out server live on public URL

const endpointSecret = process.env.ENDPOINT_URL;

server.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  (request, response) => {
    const sig = request.headers["stripe-signature"];

    let event;

    try {
      event = stripe.webhooks.constructEvent(request.body, sig, endpointSecret);
    } catch (err) {
      response.status(400).send(`Webhook Error: ${err.message}`);
      return;
    }

    // Handle the event
    switch (event.type) {
      case "payment_intent.succeeded":
        const paymentIntentSucceeded = event.data.object;
        console.log({ paymentIntentSucceeded });
        // Then define and call a function to handle the event payment_intent.succeeded
        break;
      // ... handle other event types
      default:
        console.log(`Unhandled event type ${event.type}`);
    }

    // Return a 200 response to acknowledge receipt of the event
    response.send();
  }
);
// JWT options

const opts = {};
opts.jwtFromRequest = cookieExtractor;
opts.secretOrKey = process.env.JWT_SECRET_KEY; // TODO: should not be in code;

// Middleware
server.use(express.static(path.resolve(__dirname, "build")));
server.use(
  session({
    secret: process.env.SESSION_KEY,
    resave: false,
    saveUninitialized: false,
  })
);
server.use(cookieParser());

// Initialize Passport
server.use(passport.initialize());
server.use(passport.session());

server.use(
  cors({
    exposedHeaders: ["X-Total-Count"],
  })
);
// server.use(express.raw({ type: "application/json" }));
server.use(express.json());

server.use("/products", isAuth(), productsRouter.router);
server.use("/brands", isAuth(), brandsRouter.router);
server.use("/categories", isAuth(), categoryRouter.router);
server.use("/users", isAuth(), UserRouter.router);
server.use("/auth", AuthRouter.router);
server.use("/Cart", isAuth(), CartRouter.router);
server.use("/orders", isAuth(), OrderRouter.router);

server.get("*", (req, res) =>
  res.sendFile(path.resolve("build", "index.html"))
);

// Passport strategy
passport.use(
  "local",

  new LocalStrategy({ usernameField: "email" }, async function (
    email,
    password,
    done
  ) {
    try {
      const user = await User.findOne({ email: email }).exec();
      console.log(email, password, user);
      if (!user) {
        return done(null, false, { message: "no such user email" });
      }

      crypto.pbkdf2(
        password,
        user.salt,
        310000,
        32,
        "sha256",
        async function (err, hashedPassword) {
          if (
            !crypto.timingSafeEqual(
              Buffer.from(user.password, "hex"),
              hashedPassword
            )
          ) {
            return done(null, false, { message: "invalid credentials" });
          }
          const token = jwt.sign(
            sanitizeUser(user),
            process.env.JWT_SECRET_KEY
          );
          done(null, { id: user.id, role: user.role });
        }
      );
    } catch (err) {
      done(err);
    }
  })
);

passport.use(
  "jwt",
  new JwtStrategy(opts, async function (jwt_payload, done) {
    // console.log({ jwt_payload });
    try {
      const user = await User.findById(jwt_payload.id);
      if (user) {
        return done(null, sanitizeUser(user)); // this calls serializer
      } else {
        return done(null, false);
      }
    } catch (err) {
      return done(err, false);
    }
  })
);
passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, { id: user.id, role: user.role });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

// Payments

// This is your test secret API key.
const stripe = require("stripe")(process.env.STRIPE_SERVER_KEY);

server.post("/create-payment-intent", async (req, res) => {
  try {
    const { totalAmount, orderId } = req.body;
    const paymentIntent = await stripe.paymentIntents.create({
      amount: totalAmount * 100, // for decimal compensation
      currency: "inr",
      description: "Payment for your order",

      shipping: {
        name: "John Doe",
        address: {
          line1: "456 Shipping St",
          postal_code: "67890",
          city: "Shipping City",
          state: "CA",
          country: "US",
        },
      },
      metadata: {
        orderId,
      },
    });

    res.send({
      clientSecret: paymentIntent.client_secret,
    });
  } catch (error) {
    console.error("Error creating payment intent:", error.message);
    res.status(500).send("Internal Server Error");
  }
});

// Database connection
const connectToMongoDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URL);
    console.log("Connected to MongoDB");
  } catch (error) {
    console.error("MongoDB connection error:", error.message);
  }
};

// Call the function to connect to MongoDB
connectToMongoDB();

server.listen(process.env.PORT, () => {
  console.log("Server is started on port 8080");
});
