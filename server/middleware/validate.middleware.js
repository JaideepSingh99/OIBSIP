import {ApiError} from "./error.middleware.js";

export const validate = (schema) => async (req, res, next) => {
    try {
        req.body = await schema.validate(req.body, {
            abortEarly: false,
            stripUnknown: true,
        });
        next();
    } catch (error) {
        const message = error.errors ? error.errors.join(', ') : 'Validation error';
        next(new ApiError(400, message));
    }
}