const mongoose = require('mongoose')

const url = "mongodb+srv://anosvoldigoad145:%40Apwg2321@cluster0.rfzfasb.mongodb.net/test_kelontong"

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