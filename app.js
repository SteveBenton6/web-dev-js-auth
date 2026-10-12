const path = require("path");

const express = require("express");
const session = require("express-session");
const mongodbStore = require("connect-mongodb-session");
const { ObjectId } = require("mongodb");

const db = require("./data/database");
const demoRoutes = require("./routes/demo");

const MongoDBStore = mongodbStore(session);

const app = express();

const sessionStore = new MongoDBStore({
  uri: "mongodb://localhost:27017",
  databaseName: "auth-demo",
  collection: "sessions",
});

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.static("public"));
app.use(express.urlencoded({ extended: false }));

app.use(
  session({
    secret: "super-top-secret",
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    // cookie: {
    //   maxAge: 30 * 24 * 60 * 60 * 1000
    // }
  }),
);

app.use(async function (req, res, next) {
  res.locals.isAuth = false;
  res.locals.isAdmin = false;

  const user = req.session.user;
  const isAuth = req.session.isAuthenticated;

  if (!user || !isAuth) {
    return next();
  }

  try {
    const userDoc = await db
      .getDb()
      .collection("users")
      .findOne({ _id: ObjectId.createFromHexString(req.session.user.id) });

    if (!userDoc) {
      return next();
    }

    // const isAdmin = userDoc.isAdmin;

    res.locals.isAuth = isAuth;
    res.locals.isAdmin = userDoc.isAdmin === true;
    next();
  } catch (error) {
    next(error);
  }
});

app.use(demoRoutes);

app.use(function (error, req, res, next) {
  res.render("500");
});

db.connectToDatabase().then(function () {
  app.listen(3000);
});
