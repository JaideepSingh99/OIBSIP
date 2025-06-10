import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'User name is required'],
        trim: true,
        minLength: [3, 'Name must be at least 3 characters'],
        maxLength: [50, 'Name must be at most 50 characters'],
    },
    email: {
        type: String,
        required: [true, 'User email is required'],
        unique: true,
        lowercase: true,
        trim: true,
        match: [/\S+@\S+\.\S+/, 'Please fill a valid email address']
    },
    password: {
        type: String,
        required: [true, 'User password is required'],
        minLength: [6, 'Password must be at least 6 characters'],
    },
    phone: {
        type: String,
        default: null
    },
    address: {
        street: String,
        city: String,
        state: String,
        pincode: String,
        country: String,
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    },
    isEmailVerified: {
        type: Boolean,
        default: false
    },
    verificationToken: {
        type: String,
    },
    resetPasswordToken: {
        type: String,
    },
    resetPasswordExpires: {
        type: Date,
    }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

export default User;