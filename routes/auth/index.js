const express = require('express');
const router = express.Router();

const authController =  require('../../Controllers/auth/auth')

//register user or owner
router.post('/register', authController.Register);
router.post('/login', authController.Login);
router.get('/verify', authController.VerifyEmail);
router.post('/forgot-password', authController.forgotPassword);
router.post('/reset-password', authController.resetPassword);



module.exports = router;