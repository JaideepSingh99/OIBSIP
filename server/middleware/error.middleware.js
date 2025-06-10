import { NODE_ENV} from "../config/env.js";

export class ApiError extends Error {
    constructor(statusCode, message, isOperational = true) {
        super(message);
        this.statusCode = statusCode;
        this.isOperational = isOperational;
        this.success = false;
    }
}

export const asyncHandler = (fn) => {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
};

export const notFoundHandler = (req, res, next) => {
    const error = new ApiError(404, `Route ${req.originalUrl} not found`);
    next(error);
}

export const errorMiddleware = (err, req, res, next) => {
    try {
        let error = { ...err };
        error.message = err.message;

        // Log error
        if (NODE_ENV === 'development') {
            console.error('Error Details:', {
                message: err.message,
                stack: err.stack,
                url: req.url,
                method: req.method
            });
        }

        // MongoDB CastError
        if (err.name === 'CastError') {
            const message = `Resource not found with id: ${err.value}`;
            error = new ApiError(404, message);
        }

        // MongoDB Duplicate Key Error
        if (err.code === 11000) {
            const field = Object.keys(err.keyValue)[0];
            const message = `${field} already exists`;
            error = new ApiError(400, message);
        }

        // MongoDB Validation Error
        if (err.name === 'ValidationError') {
            const message = Object.values(err.errors).map(val => val.message).join(', ');
            error = new ApiError(400, message);
        }

        // JWT Errors
        if (err.name === 'JsonWebTokenError') {
            error = new ApiError(401, 'Invalid token');
        }
        if (err.name === 'TokenExpiredError') {
            error = new ApiError(401, 'Token expired');
        }

        // Rate limit errors
        if (err.status === 429) {
            error = new ApiError(429, 'Too many requests');
        }

        const response = {
            success: false,
            error: error.message || 'Server error'
        };

        if(NODE_ENV === 'development') {
            response.stack = error.stack;
        }

        res.status(error.statusCode || 500).json(response);
    } catch (error) {
        console.log(`Error Middleware Error: ${error}`);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
};