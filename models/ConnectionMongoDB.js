const mongoose = require('mongoose')

const url = "mongodb+srv://kelontong:kelontong@cluster0.fdin0xy.mongodb.net/?retryWrites=true&w=majority"

const ConnectionDB = async () => {
    try {
        const Connect = await mongoose.connect(url)
        console.log(`Mongo Connected : ${ Connect.connection.host }`)
    } catch (error) {
        console.log(error)
        // process.exit(1)
    }
}

module.exports = ConnectionDB