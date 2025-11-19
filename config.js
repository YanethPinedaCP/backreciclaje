const mysql = require('mysql2/promise');
require('dotenv').config();

const dbConfig = {
    host: process.env.DB_HOST ,
    user: process.env.DB_USER ,
    password: process.env.DB_PASSWORD ,
    database: process.env.DB_DATABASE,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

const poolPromise = mysql.createPool(dbConfig);

poolPromise.getConnection()
    .then(connection => {
        console.log('Conexión exitosa a MySQL');
        console.log(`   Base de datos: ${dbConfig.database}`);
        console.log(`   Servidor: ${dbConfig.host}`);
        connection.release();
    })
    .catch(err => {
        console.error('Error de conexión a MySQL:', err.message);
    });

module.exports = { 
    poolPromise,
    mysql
};