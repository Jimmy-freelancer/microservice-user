const http = require('http');
const app = require('./app');
const dotenv = require('dotenv');
const { initializeSocket } = require('./socket'); 


dotenv.config();

const port = process.env.USER_PORT || 3001;
const server = http.createServer(app);

initializeSocket(server);

server.listen(port, () => {
    console.log(`User Server is running on port ${port}`);
});