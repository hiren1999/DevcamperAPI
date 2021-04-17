const ErrorResponse = require("../utils/errorResponse");
const asyncHandler = require("../middleware/async");
const User = require("../models/User");

// @desc   Register user
// @route  POST /api/v1/auth/register
// @access Public
exports.register = asyncHandler(async (req, res, next) => {
    const { name, email, password, role } = req.body;

    // CREATE USER
    const user = await User.create({
        name,
        email,
        password,
        role,
    });

    sendTokenResponse(user, 200, res);
});

// @desc   Login user
// @route  POST /api/v1/auth/login
// @access Public
exports.login = asyncHandler(async (req, res, next) => {
    const { email, password } = req.body;

    // VALIDATE EMAIL AND PASSWORD
    if (!email || !password) {
        return next(
            new ErrorResponse("PLEASE ENTER VALID EMAIL AND PASSWORD", 400)
        );
    }

    // CHECK FOR USER
    const user = await User.findOne({ email }).select("+password");
    if (!user) {
        return next(new ErrorResponse("INVALID EMAIL AND PASSWORD", 401));
    }

    // CHECK IF PASSWORD MATCHES
    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
        return next(new ErrorResponse("INVALID EMAIL AND PASSWORD", 401));
    }

    sendTokenResponse(user, 200, res);
});

// GET TOKEN FROM MODEL, CREATE COOKIE AND SEND RESPONSE
const sendTokenResponse = (user, statusCode, res) => {
    // CREATE TOKEN
    const token = user.getSignedJwtToken();

    const options = {
        expires: new Date(
            Date.now() + process.env.JWT_COOKIE_EXPIRE * 24 * 60 * 60 * 1000
        ),
        httpOnly: true,
    };

    if (process.env.NODE_ENV === "production") {
        options.secure = true;
    }

    res.status(statusCode).cookie("token", token, options).json({
        success: true,
        token,
    });
};
