import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

import User from "../models/user.model.js";
import {ApiError, asyncHandler} from "../middleware/error.middleware.js";
import {JWT_EXPIRES_IN, JWT_RESET_EXPIRES_IN, JWT_SECRET} from "../config/env.js";
import user from "debug";


export const register = asyncHandler(async (req, res, next) => {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        const { name, email, password } = req.body;

        const existingUser = await User.findOne({ email });
        if(existingUser) {
            throw new ApiError(400, 'User already exists');
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const user = await User.create([{
            name,
            email,
            password: hashedPassword
        }], { session });

        user[0].verificationToken = jwt.sign({userId: user[0]._id}, JWT_SECRET, {expiresIn: JWT_EXPIRES_IN});

        await user[0].save({ session });

        await session.commitTransaction();
        await session.endSession();

        res.status(201).json({
            success: true,
            data: {
                user: user[0],
            }
        });
    } catch (error) {
        await session.abortTransaction();
        await session.endSession();
        next(error);
    }
});

export const login = asyncHandler(async (req, res, next) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if(!user) {
        throw new ApiError(401, 'Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if(!isPasswordValid) {
        throw new ApiError(401, 'Invalid credentials');
    }

    const isEmailVerified = user.isEmailVerified;
    if(!isEmailVerified) {
        throw new ApiError(401, 'Please verify your email address');
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

    res.cookie('token', token, {
        httpOnly: true,
        sameSite: 'strict',
    });

    res.status(200).json({
        success: true,
        message: 'Login successful',
        data: {
            user: user
        }
    });
});

export const logout = asyncHandler(async (req, res, next) => {
    res.clearCookie('token', {
        httpOnly: true,
        sameSite: 'strict',
    });

    res.status(200).json({
        success: true,
        message: 'Logout successful'
    });
});

export const verifyEmail = asyncHandler(async (req, res, next) => {
    const { token } = req.params;

    let decode;
    try {
        decode = jwt.verify(token, JWT_SECRET);
    } catch (error) {
        throw new ApiError(400, 'Invalid or expired token');
    }

    const user = await User.findById(decode.userId);
    if(!user) {
        throw new ApiError(404, 'User not found');
    }

    if(user.isEmailVerified) {
        res.status(200).json({
            success: true,
            message: 'Email already verified',
        });
    }

    user.isEmailVerified = true;
    user.verificationToken = null;
    await user.save();

    res.status(200).json({
        success: true,
        message: 'Email verified successfully',
    });
});

export const forgotPassword = asyncHandler(async (req, res, next) => {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if(!user) {
        return res.status(200).json({
            success: true,
            message: 'Password reset link sent to your email',
        });
    }

    user.resetPasswordToken = jwt.sign({ userId: user._id}, JWT_SECRET, {expiresIn: JWT_RESET_EXPIRES_IN});
    user.resetPasswordExpires = Date.now() + (10 * 60 * 1000);
    await user.save();

    res.status(200).json({
        success: true,
        message: 'Password reset link sent to your email',
        data: {
            user: user
        }
    });
});

export const resetPassword = asyncHandler(async (req, res, next) => {
    const { token, newPassword } = req.body;

    let decode;
    try {
        decode = jwt.verify(token, JWT_SECRET);
    } catch (error) {
        throw new ApiError(400, 'Invalid or expired token');
    }

    const user = await User.findById(decode.userId);
    if(!user || user.resetPasswordToken !== token || Date.now() > user.resetPasswordExpires) {
        throw new ApiError(404, 'Invalid or expired token');
    }

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;
    await user.save();

    res.status(200).json({
        success: true,
        message: 'Password reset successful',
    });
});