import { User } from "../models/user.js";
import bcrypt from "bcrypt";

import { sendCookie } from "../utils/features.js";
import ErrorHandler from "../middlewares/error.js";

export const login = async (req, res, next) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email }).select("+password");
  if (!user)
    return res.status(404).json({
      message: "invalid email or password",
    });
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch)
    return res.status(404).json({
      success: false,
      message: "invalid email or password",
    });
  sendCookie(user, res, `welcome back ${user.name}`, 200);
};

export const register = async (req, res) => {
  const { name, email, password } = req.body;
  let user = await User.findOne({ email });
  if (user)
    return res.status(404).json({
      success: false,
      message: "user already exist",
    });
  const hashPassword = await bcrypt
    .hash(req.body.password, 10)
    .catch((error) => {
      console.log(error.message);
    });

  user = await User.create({ name, email, password: hashPassword });
  sendCookie(user, res, "created", 201);
};

export const getMyProfile = async (req, res) => {
  res.status(200).json({
    success: true,
    user: req.user,
  });
};

export const logout = (req, res) => {
  res
    .status(200)
    .cookie("token", "", {
      expires: new Date(Date.now()),
      sameSite: process.env.NODE_ENV === "Development" ? "lax" : "none",
      secure: process.env.NODE_ENV === "Development" ? false : true,
    })
    .json({
      success: true,
      message: "logout",
    });
};
