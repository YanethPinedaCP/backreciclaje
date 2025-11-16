const mysql = require('mysql2/promise');
require('dotenv').config();

const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_DATABASE || 'separapp_bd',
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    connectTimeout: 10000,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0
};

console.log('🔧 Configurando conexión MySQL...');
console.log(`   Host: ${dbConfig.host}`);
console.log(`   Database: ${dbConfig.database}`);
console.log(`   User: ${dbConfig.user}`);

const poolPromise = mysql.createPool(dbConfig);

// Test de conexión
poolPromise.getConnection()
    .then(connection => {
        console.log('✅ Conexión exitosa a MySQL');
        console.log(`   📊 Base de datos: ${dbConfig.database}`);
        console.log(`   🌐 Servidor: ${dbConfig.host}`);
        connection.release();
    })
    .catch(err => {
        console.error('❌ Error de conexión a MySQL:', err.message);
        console.error('💡 Verifica las variables de entorno DB_*');
    });

module.exports = { 
    poolPromise,
    mysql
};
