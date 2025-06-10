import * as yup from 'yup';

export const registerSchema = yup.object({
    name: yup.string().required('Name is required').min(3),
    email: yup.string().email('Invalid email').required('Email is required'),
    password: yup.string().required('Password is required').min(6)
});

export const loginSchema = yup.object({
    email: yup.string().email('Invalid email').required('Email is required'),
    password: yup.string().required('Password is required')
});