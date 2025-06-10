import { Router } from 'express';
import {
    forgotPassword,
    login,
    logout,
    register,
    resetPassword,
    verifyEmail
} from "../controller/auth.controller.js";
import {validate} from "../middleware/validate.middleware.js";
import {loginSchema, registerSchema} from "../validations/auth.validation.js";

const authRouter = Router();

authRouter.post('/register', validate(registerSchema), register);
authRouter.post('/login', validate(loginSchema), login);
authRouter.post('/logout', logout);
authRouter.post('/verify-email/:token', verifyEmail);
authRouter.post('/forgot-password', forgotPassword);
authRouter.post('/reset-password', resetPassword);

export default authRouter;