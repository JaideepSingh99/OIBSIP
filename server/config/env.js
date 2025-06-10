import { config } from 'dotenv';

config({ path: `.env.${ process.env.NODE_ENV || 'development' }.local` });

export const {
    PORT,
    NODE_ENV,
    DB_URI,
    JWT_SECRET,
    JWT_EXPIRES_IN,
    JWT_RESET_EXPIRES_IN
} = process.env;