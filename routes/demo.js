const express = require("express");
const bcrypt = require("bcryptjs");

const db = require("../data/database");

const router = express.Router();

function redirectIfAuthenticated(req, res, next) {
  if (req.session.isAuthenticated) {
    return res.redirect("/admin");
  }

  next();
}

function requireAuth(req, res, next) {
  if (!req.session.isAuthenticated) {
    return res.status(401).render("401");
  }

  next();
}

router.get("/", function (req, res) {
  if (req.session.isAuthenticated) {
    return res.redirect("/admin");
  }

  res.render("welcome");
});

router.get("/signup", redirectIfAuthenticated, function (req, res) {
  let sessionInputData = req.session.inputData;
  if (!sessionInputData) {
    sessionInputData = {
      hasError: false,
      email: "",
      confirmEmail: "",
      password: "",
    };
  }

  req.session.inputData = null;

  res.render("signup", { inputData: sessionInputData });
});

router.get("/login", redirectIfAuthenticated, function (req, res) {
  res.render("login");
});

router.post("/signup", async function (req, res) {
  const userData = req.body;
  const enteredEmail = (userData.email || "").trim();
  const enteredConfirmEmail = (userData["confirm-email"] || "").trim();
  const enteredPassword = (userData.password || "").trim();

  if (
    !enteredEmail ||
    !enteredConfirmEmail ||
    !enteredPassword ||
    enteredPassword.length < 9 ||
    enteredEmail !== enteredConfirmEmail ||
    !enteredEmail.includes("@")
  ) {
    req.session.inputData = {
      hasError: true,
      message: "invalid input - please check your data.",
      email: enteredEmail,
      confirmEmail: enteredConfirmEmail,
      password: enteredPassword,
    };

    req.session.save(function () {
      res.redirect("/signup");
    });
    return;
  }

  const existingUser = await db
    .getDb()
    .collection("users")
    .findOne({ email: enteredEmail });

  if (existingUser) {
    console.log("User Already Exists");
    return res.redirect("/signup");
  }

  const hashedPassword = await bcrypt.hash(enteredPassword, 12);

  const user = {
    email: enteredEmail,
    password: hashedPassword,
  };

  await db.getDb().collection("users").insertOne(user);
  res.redirect("/login");
});

router.post("/login", async function (req, res) {
  const userData = req.body;
  const enteredEmail = (userData.email || "").trim();
  const enteredPassword = userData.password || "";

  const existingUser = await db
    .getDb()
    .collection("users")
    .findOne({ email: enteredEmail });

  if (!existingUser) {
    console.log("Could not log in - user doesn't exist!");
    return res.redirect("/login");
  }

  const passwordsAreEqual = await bcrypt.compare(
    enteredPassword,
    existingUser.password,
  );

  if (!passwordsAreEqual) {
    console.log("Could not log in - passwords don't match!");
    return res.redirect("/login");
  }

  req.session.user = {
    id: existingUser._id.toString(),
    email: existingUser.email,
  };
  req.session.isAuthenticated = true;
  req.session.save(function () {
    res.redirect("/admin");
  });
});

router.get("/admin", requireAuth, function (req, res) {
  if (!req.session.isAuthenticated) {
    // if (!req.session.user)
    return res.status(401).render("401");
  }
  res.render("admin");
});

router.post("/logout", function (req, res) {
  // req.session.destroy(function (error) {
  //   if (error) {
  //     console.log("Could not log out - please try again.");
  //     return res.redirect("/admin");
  //   }
  // });
  req.session.user = null;
  req.session.isAuthenticated = false;
  res.redirect("/");
});

module.exports = router;
