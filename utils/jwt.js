const jwt = require("jsonwebtoken");
require("dotenv").config();

const createToken = (user) => {
  return { name: user.name, userId: user._id };
};

const genJWT = (payload) => {
  return jwt.sign(payload, process.env.JWT_SECRET);
};

const verifyToken = (payload) => {
  return jwt.verify(payload, process.env.JWT_SECRET);
};

const attachCookiesToRes = (res, accessToken, refreshToken) => {
  const accessTokenJWT = genJWT(accessToken);
  const refreshTokenJWT = genJWT({ accessToken, refreshToken });

  const expiryDate = 1000 * 60 * 15;
  const oneMonth = 1000 * 3600 * 24 * 30;

  res.cookie("accessToken", accessTokenJWT, {
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    maxAge: new Date(Date.now() + expiryDate),
    signed: true,
  });

  res.cookie("refreshToken", refreshTokenJWT, {
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    expires: new Date(Date.now() + oneMonth),
    signed: true,
  });
};

module.exports = { createToken, genJWT, verifyToken, attachCookiesToRes };
