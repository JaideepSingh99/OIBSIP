import {ApiError, asyncHandler} from "./error.middleware.js";
import {JWT_SECRET} from "../config/env.js";
import User from "../models/user.model.js";

export const protect = asyncHandler(async (req, res, next) => {
    let token;

    if(req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    } else if(req.cookies.token) {
        token = req.cookies.token;
    }

    if(!token) {
        return next(new ApiError(401, 'Not authorized, please login'));
    }

    let decode;
    try {
        decode = jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return next(new ApiError(401, ''));
    }

    const user = await User.findById(decode.userId);
    if(!user) {
        return next(new ApiError(404, 'User not found'));
    }

    if(!user.isEmailVerified) {
        return next(new ApiError(401, 'Please verify your email address'));
    }

    req.user = user;

    next();
});

const adminOnly = asyncHandler(async (req, res, next) => {
    if(req.user.role !== 'admin') {
        return next(new ApiError(401, 'Admin access only'));
    }
    next();
});