const express = require('express')
const routes = express.Router()


//Auth 
const Auth = require('./auth/index')
routes.use('/auth', Auth)


module.exports=routes