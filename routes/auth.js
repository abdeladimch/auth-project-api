const express = require("express");
const { signup, login, logout } = require("../controllers/auth");
const router = express.Router();
const authUser = require("../middlewares/authMiddleware");
router.post("/signup", signup);
router.post("/login", login);
router.get("/logout", authUser, logout);
module.exports = router;
