require("dotenv").config();
const { Unauthenticated } = require("../errors");
const { verifyToken } = require("../utils/jwt");
const { attachCookiesToRes } = require("../utils/jwt");

const authUser = async (req, res, next) => {
  const { accessToken, refreshToken } = req.signedCookies;
  if (!accessToken && !refreshToken) {
    throw new Unauthenticated("Authentication failed!");
  }
  if (accessToken) {
    const decoded = verifyToken(accessToken);
    req.user = decoded;
    return next();
  }
  const decoded = verifyToken(refreshToken);
  req.user = decoded.accessToken;
  attachCookiesToRes(res, decoded.accessToken, decoded.refreshToken);

  next();
};

module.exports = authUser;
