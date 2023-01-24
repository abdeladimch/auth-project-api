const express = require("express");
const { signup, login, logout, verifyEmail } = require("../controllers/auth");
const router = express.Router();
const authUser = require("../middlewares/authMiddleware");
router.post("/signup", signup);
router.post("/login", login);
router.get("/verify-email", verifyEmail);
router.get("/logout", authUser, logout);
module.exports = router;
