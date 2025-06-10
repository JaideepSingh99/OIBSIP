import { Router } from 'express';
import {
    forgotPassword,
    login,
    logout,
    register,
    resetPassword,
    verifyEmail
} from "../controller/auth.controller.js";

const authRouter = Router();

authRouter.post('/register', register);
authRouter.post('/login', login);
authRouter.post('/logout', logout);
authRouter.post('/verify-email/:token', verifyEmail);
authRouter.post('/forgot-password', forgotPassword);
authRouter.post('/reset-password', resetPassword);

export default authRouter;