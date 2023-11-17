const Mongoose = require('mongoose')

var Schema = new Mongoose.Schema({
    name: { type: String,required:true },
    password: { type: String,required:true },
    email: { type: String,required:true },
    phone_number: { type: String,required:true },
    alamat: { type: String,required:true },
    isVerified: {type:Boolean, default: false},
    verificationToken: {type:String},
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date },
    role: {type: String,required:true}
})

const User = Mongoose.model('User', Schema)

module.exports = User