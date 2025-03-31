const express = require('express');
const dotenv = require('dotenv');
dotenv.config();

const app = express();
const userRoutes = require('../user/routes/user.route');
const cookieParser = require('cookie-parser');  
const connectDB = require('../user/db/db');
const RabbitMQ = require('../user/services/rabbitmq')
const cors = require('cors');



connectDB();
RabbitMQ.connect();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors());

app.use('/test', (req, res) => {
    res.send('Hello from user service')
});

app.use('/', userRoutes)



module.exports = app;