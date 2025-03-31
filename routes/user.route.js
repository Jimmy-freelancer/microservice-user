const express = require('express');
const router = express.Router();
const { body, param } = require("express-validator")
const userController = require('../controllers/user.controller');
const authMiddleware = require('../middlewares/user.middleware');


router.post('/register', [
    body('email').isEmail().withMessage('Invalid Email'),
    body('fullname.firstname').isLength({ min: 3 }).withMessage('First name must be at least 3 characters long'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
    body('phone').isLength({ min: 10, max: 15 }).withMessage('Invalid Phone Number')
],
    userController.registerUser
)

router.post('/login', [
    body('email').isEmail().withMessage('Invalid Email'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
],
    userController.loginUser
)

router.get('/profile', authMiddleware.authUser, userController.getUserProfile)

router.get('/logout', authMiddleware.authUser, userController.logoutUser)

router.get('/user', userController.getUserById);

router.post('/send-otp', [
    body('phone')
        .trim()
        .isLength({ min: 10, max: 15 })
        .withMessage('Invalid Phone Number')
], userController.sendOtp);

router.post('/verify-otp', [
    body('otp')
        .trim()
        .isLength({ min: 6, max: 6 })
        .withMessage('Invalid OTP'),
    body('phone')
        .trim()
        .isLength({ min: 10, max: 15 })
        .withMessage('Invalid Phone Number')
], userController.verifyOtp);

router.post('/resend-otp', [
    body('phone')
        .trim()
        .isLength({ min: 10, max: 15 })
        .withMessage('Invalid Phone Number')
], userController.resendOtp);

module.exports = router;