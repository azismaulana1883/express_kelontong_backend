const Cryptr = require('cryptr');
const CryptrNew = new Cryptr('secret-key-access');
const JWT = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const UserModelsMongo = require('../../models/scheme/User');

// Konfigurasi transporter untuk Nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'indra.kurniawan1433@gmail.com',
        pass: 'ubpnqeblbwjmoipk'
    }
});

// Fungsi untuk mengirim email verifikasi
function sendVerificationEmail(email, verificationToken) {
    const mailOptions = {
        from: 'your-email@gmail.com',
        to: email,
        subject: 'Email Verification',
        text: `Click the following link to verify your email: http://localhost:7600/api/v1/auth/verify?email=${email}&token=${verificationToken}`
    };

    // http://localhost:7600/api/v1/auth/verify?email=example@example.com&token=your-verification-token


    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error(error);
        } else {
            console.log('Email sent: ' + info.response);
        }
    });
}

async function Register(req, res, next) {
    const { name, email, password, phone_number, alamat, role } = req.body;

    try {
        let getUser = await UserModelsMongo.findOne({
            email: email
        });

        if (getUser) {
            res.status(400).send({
                message: 'Data is exists, please create another one!',
                success: false,
                statusCode: 400
            });
        } else {
            let dataPassingToDB = {
                name: name,
                password: CryptrNew.encrypt(password),
                email: email,
                phone_number: phone_number,
                alamat: alamat,
                role: role,
                isVerified: false,
                verificationToken: generateUniqueToken() // Generate unique token for verification
            };

            let createdData = await UserModelsMongo.create(dataPassingToDB);

            const userConfig = {
                name: createdData.name,
                email: createdData.email,
                phone_number: createdData.phone_number,
                alamat: createdData.alamat,
                verificationToken : createdData.verificationToken,
                role: createdData.role
            };

            if (!createdData) {
                res.status(400).send({
                    message: 'Wrong username or password',
                    success: false,
                    statusCode: 400
                });
            } else {
                // Kirim email verifikasi setelah berhasil mendaftar
                sendVerificationEmail(email, dataPassingToDB.verificationToken);

                res.send({
                    data: userConfig,
                    message: 'Successfully created user data! Please check your email for verification.',
                    success: true,
                    statusCode: 201
                });
            }
        }
    } catch (error) {
        console.error(error);
        res.status(400);
    }
}

async function VerifyEmail(req, res, next) {
    const { email, token } = req.query;

    try {
        let user = await UserModelsMongo.findOne({ email: email, verificationToken: token });

        if (!user) {
            console.error('Invalid verification token or email:', email, token);
            return res.status(400).send({
                message: 'Invalid verification token!',
                success: false,
                statusCode: 400
            });
        }

        // Update isVerified menjadi true langsung saat tautan diklik
        const updateResult = await UserModelsMongo.updateOne(
            { email: email, verificationToken: token },
            { $set: { isVerified: true }, $unset: { verificationToken: 1 } } // Hapus token setelah verifikasi
        );

        if (updateResult.modifiedCount !== 1) {
            console.error('Failed to update isVerified:', email, token);
            return res.status(500).send({
                message: 'Failed to update isVerified!',
                success: false,
                statusCode: 500
            });
        }

        console.log('Email verification successful:', email, token);
        res.status(200).send({
            message: 'Email verification successful!',
            success: true,
            statusCode: 200
        });
    } catch (error) {
        console.error('Error in VerifyEmail:', error);
        res.status(500).send({
            message: 'Internal Server Error',
            success: false,
            statusCode: 500
        });
    }
}


async function Login(req, res, next) {
    const { email } = req.body;

    // Get Users Exist
    try {
        let getUser = await UserModelsMongo.aggregate([
            {
                $match: { email: email }
            }
        ]);

        if (getUser.length < 1) {
            res.status(400).send({
                message: 'Data is not exists!',
                statusCode: 400
            });
        } else {
            let passwordUser = CryptrNew.decrypt(getUser[0].password);

            if (req.body.password !== passwordUser) {
                res.status(400).send({
                    message: 'Username or Password is wrong!',
                    statusCode: 400
                });
            } else if (!getUser[0].isVerified) {
                res.status(401).send({
                    message: 'Email is not verified. Please verify your email first.',
                    statusCode: 401
                });
            } else {
                let expiredToken = Math.floor(Date.now() / 1000) + 60 * 60;
                let createAccessToken = JWT.sign(
                    {
                        exp: expiredToken,
                        data: {
                            name: getUser[0].name,
                            email: getUser[0].email,
                            id: getUser[0].id,
                            role: getUser[0].role
                        }
                    },
                    'secret-key-access'
                );

                let dataPassingClient = {
                    access_token: createAccessToken, // access token expired 1 day
                    refresh_token: createAccessToken, // refresh token expired 1 month
                    expired_date: expiredToken,
                    user: getUser[0].email,
                    id: getUser[0].id,
                    role: getUser[0].role
                };

                res.status(200).send({
                    message: 'Successfully login user!',
                    statusText: 'Successfully login user!',
                    statusCode: 200,
                    success: true,
                    data: dataPassingClient
                });
            }
        }
    } catch (error) {
        console.error(error);
        res.status(400);
    }
}


// Fungsi untuk menghasilkan token verifikasi unik
function generateUniqueToken() {
    const characters = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    let token = '';

    for (let i = 0; i < 32; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        token += characters[randomIndex];
    }

    return token;
}


module.exports = {
    Register,
    VerifyEmail,
    Login,
    generateUniqueToken
};
