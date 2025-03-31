const mongoose = require('mongoose');
require('dotenv').config();

function connectToDb() {
    const dbConnect = process.env.DB_USER;
    if (!dbConnect) {
        console.error('DB_CONNECT environment variable is not set');
        return;
    }

    mongoose.connect(dbConnect, { useNewUrlParser: true, useUnifiedTopology: true })
        .then(() => {
            console.log('Connected to DB');
        })
        .catch(err => {
            console.error('Failed to connect to DB:', err);
        });
}

module.exports = connectToDb;