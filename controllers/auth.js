const { StatusCodes } = require("http-status-codes");
const { BadRequest, Unauthenticated } = require("../errors");
const User = require("../models/User");
const bcrypt = require("bcrypt");
const { createToken, attachCookiesToRes } = require("../utils/jwt");
const crypto = require("crypto");
const Token = require("../models/Token");

const signup = async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    throw new BadRequest("Please fill out all fields!");
  }
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    throw new BadRequest("An account with this email already exists!");
  }

  const user = await User.create(req.body);
  res
    .status(StatusCodes.CREATED)
    .json({ user: { userId: user._id, name: user.name } });
};

const login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    throw new BadRequest("Pleas fill out all fields!");
  }
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    throw new Unauthenticated("Invalid credentials!");
  }

  const userToken = createToken(user);
  let refreshToken = "";
  const existingToken = await Token.findOne({ user: user._id });

  if (existingToken) {
    refreshToken = existingToken.refreshToken;
    attachCookiesToRes(res, userToken, refreshToken);
    return res.status(StatusCodes.OK).json({ user: userToken });
  }

  refreshToken = crypto.randomBytes(64).toString("hex");
  const userAgent = req.headers["user-agent"];
  const ip = req.ip;
  const saveToken = { userAgent, ip, refreshToken, user: user._id };
  const token = await Token.create(saveToken);

  attachCookiesToRes(res, userToken, refreshToken);
  res.status(StatusCodes.OK).json({ user: userToken });
};

const logout = async (req, res) => {
  const { userId: id } = req.user;
  await Token.findOneAndDelete({ user: id });

  res.cookie("accessToken", "", {
    httpOnly: true,
    expires: new Date(Date.now()),
  });
  res.cookie("refreshToken", "", {
    httpOnly: true,
    expires: new Date(Date.now()),
  });

  res.status(StatusCodes.OK).json({ msg: "logged out!" });
};

module.exports = { signup, login, logout };
