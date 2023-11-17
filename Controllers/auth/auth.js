const Cryptr = require('cryptr')
const CryptrNew = new Cryptr('secret-key-access')
const JWT = require('jsonwebtoken')
const UserModelsMongo = require('../../models/scheme/User')

async function Register(req, res, next) {
    const { name, email, password,phone_number,alamat,role } = req.body

    try {
        let getUser = await UserModelsMongo.findOne({
            email: email
        })

        if ( getUser ) {
            res.status(400).send({
                message: 'Data is exists, please create another one!',
                success:false,
                statusCode: 400
            })
        } else {
            let dataPassingToDB = {
                name: name,
                password: CryptrNew.encrypt(password),
                email: email,
                phone_number: phone_number,
                alamat: alamat,
                role: role
            }
    
            let createdData = await UserModelsMongo.create(dataPassingToDB)
            const userConfig = {
                name: createdData.name,
                email:createdData.email,
                phone_number:createdData.phone_number,
                alamat:createdData.alamat,
                role:createdData.role
            }
    
            if ( !createdData ) {
                res.status(400).send({
                    message: 'wrong username or password',
                    success:false,
                    statusCode: 400
                })
            } else {
                res.send({
                    data : userConfig,
                    message: 'successfull to create data users!',
                    success:true,
                    statusCode: 201
                })
            }
        }
    } catch(error) {
        console.log(error)
        res.stats(400)
    }
}

async function Login(req, res, next) {
    const { email } = req.body

    // Get Users Exist
    try {
        let getUser = await UserModelsMongo.aggregate([
            {
                $match: {email:email}
            }
        ])

        if ( getUser.length < 1 ) {
            res.status(400).send({
                message: 'Data is not exists!',
                statusCode: 400
            })
        } else {
            let passwordUser = CryptrNew.decrypt(getUser[0].password)

            if ( req.body.password !== passwordUser ) {
                res.status(400).send({
                    message: 'Username or Password is wrong!',
                    statusCode: 400
                })
            } else {
                let expiredToken = Math.floor(Date.now() / 1000) + (60 * 60)
                let createAccessToken = JWT.sign({
                    exp: expiredToken,
                    data: {
                        name: getUser[0].name,
                        email: getUser[0].email,
                        id: getUser[0].id,
                        role: getUser[0].role
                    }
                }, 'secret-key-access')
    
                let dataPassingClient = {
                    access_token: createAccessToken, // access token expired 1 day
                    refresh_token: createAccessToken, // refresh token expired 1 month
                    expired_date: expiredToken,
                    user: getUser[0].email,
                    id: getUser[0].id,
                    role: getUser[0].role
                }
    
                res.status(200).send({
                    message: 'Successfull to login user!',
                    statusText: 'Successfull to login user!',
                    statusCode: 200,
                    success:true,
                    data: dataPassingClient
                })
            }
        }
    } catch(error) {
        console.log(error)
        res.status(400)
    }
}

module.exports = {
    Register,
    Login
}