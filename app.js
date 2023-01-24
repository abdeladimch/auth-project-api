require("dotenv").config();
require("express-async-errors");

const express = require("express");
const mongoose = require("mongoose");
const app = express();
const PORT = process.env.PORT || 3000;
const connectDB = require("./db/connect");
const notFound = require("./middlewares/notFound");
const authRouter = require("./routes/auth");
const errorHandler = require("./middlewares/errorHandler");
const cookieParser = require("cookie-parser");

const cors = require("cors");
const rateLimiter = require("express-rate-limit");
const helmet = require("helmet");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss-clean");

mongoose.set("strictQuery", true);

app.set("trus proxy", 1);
app.use(
  rateLimiter({
    windowMs: 1000 * 60 * 15,
    max: 50,
  })
);
app.use(cors());
app.use(helmet());
app.use(mongoSanitize());
app.use(xss());

app.use(express.json());
app.use(cookieParser(process.env.JWT_SECRET));

app.get("/", (req, res) => {
  res.status(200).json({ msg: "Welcome to auth api!" });
});
app.use("/api/auth", authRouter);

app.use(errorHandler);
app.use(notFound);

connectDB(process.env.MONGO_URI);

mongoose.connection.once("open", () => {
  console.log("Connected to DB!");
  app.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
  });
});
