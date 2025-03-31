const userModel = require('../models/user.model');
const userService = require('../services/user.service');
const { validationResult } = require('express-validator');
const blackListTokenModel = require('../models/blackListToken.model');
const crypto = require('crypto');
const twilio = require('twilio');
const bcrypt = require('bcrypt');
const { sendMessageToSocketId } = require('../socket');

const { subscribeToQueue, publishToQueue } = require('../services/rabbitmq');

const otpStore = new Map();
const client = new twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);


function getOtp(num) {
    return crypto.randomInt(Math.pow(10, num - 1), Math.pow(10, num)).toString();
}


module.exports.registerUser = async (req, res, next) => {

    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ message: errors.array()[0].msg });
        }

        const { fullname, email, password, phone } = req.body;
        const isUserAlready = await userModel.findOne({ email });

        if (isUserAlready) {
            return res.status(401).json({ message: 'User already exist, Please Login !' });
        }

        const hashedPassword = await userModel.hashPassword(password);

        const user = await userService.createUser({
            firstname: fullname.firstname,
            lastname: fullname.lastname,
            email,
            password: hashedPassword,
            phone
        });

        const token = user.generateAuthToken();

        res.status(200).json({ token, user });
    } catch (error) {
        res.status(400).json({ message: "Registration Failed !" });
    }

}

module.exports.loginUser = async (req, res, next) => {

    try {

        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ message: errors.array()[0].msg });
        }

        const { email, password } = req.body;

        const user = await userModel.findOne({ email }).select('+password');

        if (!user) {
            return res.status(401).json({ message: 'User not exist !!!' });
        }

        const isMatch = await user.comparePassword(password);

        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid password' });
        }

        const token = user.generateAuthToken();

        res.cookie('token', token);

        res.status(200).json({ token, user });
    } catch (error) {
        res.status(400).json({ message: "Authentication error !" });
    }
}

module.exports.getUserProfile = async (req, res, next) => {
    res.status(200).json(req.user);
}

module.exports.logoutUser = async (req, res, next) => {
    res.clearCookie('token');
    const token = req.cookies.token || req.headers.authorization.split(' ')[1];

    await blackListTokenModel.create({ token });

    res.status(200).json({ message: 'Logged out' });

}

module.exports.getUserById = async (req, res, next) => {
    try {
        const userId = req.query.userId;
        const user = await userModel.findById(userId);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json(user);
    } catch (error) {
        next(error);
    }
};


module.exports.sendOtp = async (req, res) => {
    try {
        const { phone } = req.body;
        if (!phone) {
            return res.status(400).json({ message: "Phone number is required" });
        }

        const otp = getOtp(6);
        const hashedOtp = await bcrypt.hash(otp, 10);

        otpStore.set(phone, { otp: hashedOtp, expiresAt: Date.now() + 300000 });

        await client.messages.create({
            body: `Your OTP is: ${otp}`,
            from: process.env.TWILIO_PHONE_NUMBER,
            to: phone
        });

        res.status(200).json({ message: "OTP sent successfully" });

    } catch (error) {
        res.status(500).json({ message: "Failed to send OTP", error: error.message });
    }
};


module.exports.verifyOtp = async (req, res) => {
    try {
        const { phone, otp } = req.body;
        if (!phone || !otp) {
            return res.status(400).json({ message: "Phone and OTP are required" });
        }

        const storedOtpData = otpStore.get(phone);
        if (!storedOtpData || Date.now() > storedOtpData.expiresAt) {
            otpStore.delete(phone);
            return res.status(400).json({ message: "OTP expired or invalid" });
        }

        const isOtpValid = await bcrypt.compare(otp, storedOtpData.otp);
        if (!isOtpValid) {
            return res.status(400).json({ message: "Invalid OTP" });
        }

        otpStore.delete(phone);
        res.status(200).json({ message: "OTP verified successfully" });

    } catch (error) {
        res.status(500).json({ message: "OTP verification failed", error: error.message });
    }
};

module.exports.resendOtp = async (req, res) => {
    try {
        const { phone } = req.body;
        if (!phone) {
            return res.status(400).json({ message: "Phone number is required" });
        }

        const existingOtp = otpStore.get(phone);
        if (existingOtp && Date.now() < existingOtp.expiresAt) {
            otpStore.delete(phone);
        }

        const newOtp = getOtp(6);
        const hashedOtp = await bcrypt.hash(newOtp, 10);

        otpStore.set(phone, { otp: hashedOtp, expiresAt: Date.now() + 300000 });

        await client.messages.create({
            body: `Your new OTP is: ${newOtp}`,
            from: process.env.TWILIO_PHONE_NUMBER,
            to: phone
        });

        res.status(200).json({ message: "New OTP sent successfully" });

    } catch (error) {
        res.status(500).json({ message: "Failed to resend OTP", error: error.message });
    }
};



subscribeToQueue("ride-confirmed", async (msg) => {
    const data = JSON.parse(msg);
    sendMessageToSocketId(data.user.socketId, {
        event: 'ride-confirmed',
        data
    });
});

subscribeToQueue("ride-start", async (msg) => {
    const data = JSON.parse(msg);
    console.log('Ride started');
    sendMessageToSocketId(data.user.socketId, {
        event: 'ride-started',
        data
    });
});

subscribeToQueue("ride-end", async (msg) => {
    const data = JSON.parse(msg);
    console.log('Ride ended : ' + data);
    const user = await userModel.findById(data.user);
    sendMessageToSocketId(user.socketId, {
        event: 'ride-ended',
        data
    });
});

subscribeToQueue("no-captain", async (msg) => {
    const data = JSON.parse(msg);
    console.log('No captain');
    sendMessageToSocketId(data.user.socketId, {
        event: 'no-captain',
        data
    });
});
