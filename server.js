// server.js - Backend SeparAPP
const express = require('express');
const cors = require('cors');
const { poolPromise } = require('./config');
require('dotenv').config();
const jwt = require('jsonwebtoken');

const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');

// Configuración del correo
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Verificar conexión al iniciar
transporter.verify((error, success) => {
    if (error) {
        console.log('❌ Error en configuración de correo:', error.message);
    } else {
        console.log('✅ Servidor de correo listo');
    }
});

// Función para enviar correo
async function enviarCorreoRecuperacion(correo, nombre, codigo) {
    const mailOptions = {
        from: `"SeparAPP" <${process.env.EMAIL_USER}>`,
        to: correo,
        subject: '🔐 Código de recuperación - SeparAPP',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background: linear-gradient(135deg, #8EB69B 0%, #5D9E6A 100%); padding: 30px; border-radius: 15px 15px 0 0; text-align: center;">
                    <h1 style="color: white; margin: 0;">🌿 SeparAPP</h1>
                    <p style="color: rgba(255,255,255,0.9); margin-top: 10px;">Sistema de Reciclaje Inteligente</p>
                </div>
                
                <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 15px 15px;">
                    <h2 style="color: #333;">Hola ${nombre} 👋</h2>
                    
                    <p style="color: #666; font-size: 16px;">
                        Recibimos una solicitud para restablecer tu contraseña. 
                        Usa el siguiente código de verificación:
                    </p>
                    
                    <div style="background: #8EB69B; color: white; font-size: 32px; font-weight: bold; text-align: center; padding: 20px; border-radius: 10px; letter-spacing: 8px; margin: 25px 0;">
                        ${codigo}
                    </div>
                    
                    <p style="color: #666; font-size: 14px;">
                        ⏱️ Este código expira en <strong>10 minutos</strong>.
                    </p>
                    
                    <p style="color: #999; font-size: 13px; margin-top: 30px;">
                        Si no solicitaste este código, puedes ignorar este correo. 
                        Tu cuenta está segura.
                    </p>
                    
                    <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
                    
                    <p style="color: #999; font-size: 12px; text-align: center;">
                        © 2024 SeparAPP - Todos los derechos reservados<br>
                        Este es un correo automático, por favor no respondas.
                    </p>
                </div>
            </div>
        `
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('📧 Correo enviado:', info.messageId);
        return true;
    } catch (error) {
        console.error('❌ Error al enviar correo:', error);
        return false;
    }
}

// Almacén temporal de códigos
const codigosRecuperacion = new Map();

// Generar código de 6 dígitos
function generarCodigo() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

const { JWT_ACCESS_SECRET, JWT_REFRESH_SECRET, ACCESS_EXPIRES, REFRESH_EXPIRES } = process.env;

const signAccessToken = (payload) =>
  jwt.sign(payload, JWT_ACCESS_SECRET, { expiresIn: ACCESS_EXPIRES || '15m' });

const signRefreshToken = (payload) =>
  jwt.sign(payload, JWT_REFRESH_SECRET, { expiresIn: REFRESH_EXPIRES || '7d' });


const port = process.env.PORT || 3000;
const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.get("/", async (req, res) => {
    res.json({ 
        success: true, 
        message: 'API SeparAPP funcionando correctamente',
        version: '1.0.0',
        timestamp: new Date().toISOString()
    });
})

// ==================== LOGIN ====================
app.post('/api/login', async (req, res) => {
    try {
    const correo = String(req.body?.correo || '').trim().toLowerCase();
    const contrasena = String(req.body?.contrasena || '');

    if (!correo || !contrasena) {
        return res.status(400).json({ success: false, error: 'Correo y contraseña son obligatorios' });
    }

    // Trae usuario por correo
    const [rows] = await poolPromise.execute(
        `SELECT 
            u.id_usuario, u.nombre, u.apellido, u.correo, 
            u.contrasena, u.id_estado, u.id_rol
        FROM usuarios u
        WHERE u.correo = ?
        LIMIT 1`,
        [correo]
    );

    if (!rows || rows.length === 0) {
        return res.status(401).json({ success: false, error: 'Correo o contraseña inválidos' });
    }

    const usr = rows[0];

    if (usr.id_estado === 2) {
        return res.status(403).json({ success: false, error: 'Cuenta suspendida o inactiva' });
    }

    // Verifica contraseña (hash con bcrypt)
    let ok = false;
    try {
        ok = await bcrypt.compare(contrasena, usr.contrasena);
        } catch (_) {
        ok = false;
    }

    // Si tu base aún guarda en texto plano, habilita este fallback temporal:
    if (!ok && usr.contrasena === contrasena) ok = true;

    if (!ok) {
        return res.status(401).json({ success: false, error: 'Correo o contraseña inválidas' });
    }

    // Genera tokens
    const payload = { sub: usr.id_usuario, correo: usr.correo, rol: usr.id_rol };
    const accessToken = signAccessToken(payload);
    const refreshToken = signRefreshToken(payload);

    return res.json({
        success: true,
        message: 'Inicio de sesión exitoso',
        accessToken,
        refreshToken,
        usuario: {
            id_usuario: usr.id_usuario,
            nombre: usr.nombre,
            apellido: usr.apellido,
            correo: usr.correo,
            id_rol: usr.id_rol
        }
    });
    } catch (err) {
        console.error('Error en /api/login:', err);
        return res.status(500).json({ success: false, error: 'Error interno del servidor' });
    }
});

// ==================== REGISTRO DE USUARIO ====================
app.post('/api/registro', async (req, res) => {
    try {
        const {
            nombre, 
            apellido, 
            correo, 
            contrasena,  
            telefono,
            foto
        } = req.body; 

        // PASO 1: Validar campos obligatorios
        if (!nombre || !apellido || !correo || !contrasena) {
            return res.status(400).json({ 
                success: false, 
                error: 'Nombre, apellido, correo y contraseña son obligatorios' 
            });
        }

        // PASO 2: Validar formato de correo
        const emailRegex = /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/;
        if (!emailRegex.test(correo)) {
            return res.status(400).json({ 
                success: false, 
                error: 'El correo electrónico no es válido' 
            });
        }

        // PASO 3: Validar longitud de contraseña
        if (contrasena.length < 6) {
            return res.status(400).json({ 
                success: false, 
                error: 'La contraseña debe tener al menos 6 caracteres' 
            });
        }

        // PASO 4: Verificar si el correo ya existe
        const [existingUser] = await poolPromise.execute(
            'SELECT id_usuario FROM usuarios WHERE correo = ?',
            [correo.toLowerCase().trim()]
        );

        if (existingUser && existingUser.length > 0) {
            return res.status(409).json({ 
                success: false, 
                error: 'Este correo ya está registrado' 
            });
        }

        // PASO 5: Hashear la contraseña con bcrypt
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(contrasena, salt);

        const formatearNombre = (texto) => {
            return texto.trim().split(' ').map(palabra => {
                if (!palabra) return '';
                return palabra.charAt(0).toUpperCase() + palabra.slice(1).toLowerCase();
            }).join(' ');
        };

        const nombreFormateado = formatearNombre(nombre);
        const apellidoFormateado = formatearNombre(apellido);
        const telefonoLimpio = telefono ? telefono.replace(/[\s\-]/g, '') : null;


        // PASO 6: Insertar el nuevo usuario
        const [result] = await poolPromise.execute(
            `INSERT INTO usuarios (
                nombre, 
                apellido, 
                correo, 
                contrasena, 
                telefono,
                foto, 
                id_rol,
                id_estado
            )
            VALUES (?, ?, ?, ?, ?, ?, 1, 1)`,  // id_rol=2 (Usuario normal), id_estado=1 (Activo)
            [
                nombreFormateado,
                apellidoFormateado,
                correo.toLowerCase().trim(),
                hashedPassword,
                telefonoLimpio || null,
                foto || null
            ]
        );

        // PASO 7: Obtener el usuario recién creado
        const [newUser] = await poolPromise.execute(
            `SELECT 
                id_usuario, 
                nombre, 
                apellido, 
                correo, 
                id_rol,
                fecha_creacion
            FROM usuarios 
            WHERE id_usuario = ?`,
            [result.insertId]
        );

        const usuario = newUser[0];

        // PASO 8: Generar tokens JWT
        const payload = { 
            sub: usuario.id_usuario, 
            correo: usuario.correo, 
            rol: usuario.id_rol 
        };
        const accessToken = signAccessToken(payload);
        const refreshToken = signRefreshToken(payload);

        // PASO 9: Responder con éxito
        return res.status(201).json({
            success: true,
            message: 'Usuario registrado exitosamente',
            accessToken,
            refreshToken,
            usuario: {
                id_usuario: usuario.id_usuario,
                nombre: usuario.nombre,
                apellido: usuario.apellido,
                correo: usuario.correo,
                id_rol: usuario.id_rol
            }
        });

    } catch (err) {
        console.error('Error en /api/registro:', err);
        return res.status(500).json({ 
            success: false, 
            error: 'Error al registrar usuario. Intenta nuevamente.' 
        });
    }
});

// ==================== RECUPERAR CONTRASEÑA ====================

// Almacén temporal de códigos (en memoria)

// Generar código de 6 dígitos
function generarCodigo() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// 1. Solicitar código de recuperación
// 1. Solicitar código de recuperación
app.post('/api/recuperar/solicitar', async (req, res) => {
    try {
        const correo = String(req.body?.correo || '').trim().toLowerCase();

        if (!correo) {
            return res.status(400).json({
                success: false,
                error: 'El correo es obligatorio'
            });
        }

        // Verificar si el correo existe
        const [rows] = await poolPromise.execute(
            'SELECT id_usuario, nombre FROM usuarios WHERE correo = ? LIMIT 1',
            [correo]
        );

        if (!rows || rows.length === 0) {
            return res.status(404).json({
                success: false,
                error: 'No existe una cuenta con este correo'
            });
        }

        const usuario = rows[0];
        const codigo = generarCodigo();

        // Guardar código con expiración (10 minutos)
        codigosRecuperacion.set(correo, {
            codigo: codigo,
            idUsuario: usuario.id_usuario,
            nombre: usuario.nombre,
            expira: Date.now() + (10 * 60 * 1000)
        });

        console.log(`📧 Código de recuperación para ${correo}: ${codigo}`);

        // ENVIAR CORREO REAL
        const correoEnviado = await enviarCorreoRecuperacion(
            correo, 
            usuario.nombre, 
            codigo
        );

        if (correoEnviado) {
            res.json({
                success: true,
                message: 'Código enviado al correo'
            });
        } else {
            // Si falla el envío, devolver con debug
            res.json({
                success: true,
                message: 'Código generado (error al enviar correo)',
                codigo_debug: codigo
            });
        }

    } catch (error) {
        console.error('Error en solicitar recuperación:', error);
        res.status(500).json({
            success: false,
            error: 'Error al procesar solicitud'
        });
    }
});

// 2. Verificar código
app.post('/api/recuperar/verificar', async (req, res) => {
    try {
        const correo = String(req.body?.correo || '').trim().toLowerCase();
        const codigo = String(req.body?.codigo || '').trim();

        if (!correo || !codigo) {
            return res.status(400).json({
                success: false,
                error: 'Correo y código son obligatorios'
            });
        }

        const datos = codigosRecuperacion.get(correo);

        if (!datos) {
            return res.status(400).json({
                success: false,
                error: 'No hay solicitud de recuperación para este correo'
            });
        }

        if (Date.now() > datos.expira) {
            codigosRecuperacion.delete(correo);
            return res.status(400).json({
                success: false,
                error: 'El código ha expirado. Solicita uno nuevo.'
            });
        }

        if (datos.codigo !== codigo) {
            return res.status(400).json({
                success: false,
                error: 'Código incorrecto'
            });
        }

        res.json({
            success: true,
            message: 'Código verificado correctamente',
            idUsuario: datos.idUsuario
        });

    } catch (error) {
        console.error('Error en verificar código:', error);
        res.status(500).json({
            success: false,
            error: 'Error al verificar código'
        });
    }
});

// 3. Cambiar contraseña
app.post('/api/recuperar/cambiar', async (req, res) => {
    try {
        const correo = String(req.body?.correo || '').trim().toLowerCase();
        const codigo = String(req.body?.codigo || '').trim();
        const nuevaContrasena = String(req.body?.nuevaContrasena || '');

        if (!correo || !codigo || !nuevaContrasena) {
            return res.status(400).json({
                success: false,
                error: 'Todos los campos son obligatorios'
            });
        }

        if (nuevaContrasena.length < 6) {
            return res.status(400).json({
                success: false,
                error: 'La contraseña debe tener al menos 6 caracteres'
            });
        }

        const datos = codigosRecuperacion.get(correo);

        if (!datos || datos.codigo !== codigo) {
            return res.status(400).json({
                success: false,
                error: 'Código inválido o expirado'
            });
        }

        // Hashear nueva contraseña
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(nuevaContrasena, salt);

        // Actualizar en BD
        await poolPromise.execute(
            'UPDATE usuarios SET contrasena = ?, fecha_actualizacion = NOW() WHERE correo = ?',
            [hashedPassword, correo]
        );

        // Eliminar código usado
        codigosRecuperacion.delete(correo);

        console.log(`✅ Contraseña actualizada para ${correo}`);

        res.json({
            success: true,
            message: 'Contraseña actualizada correctamente'
        });

    } catch (error) {
        console.error('Error al cambiar contraseña:', error);
        res.status(500).json({
            success: false,
            error: 'Error al cambiar contraseña'
        });
    }
});

// ==================== BASUREROS ====================

// Registrar o actualizar un basurero
app.post('/api/basureros/registro', async (req, res) => {
    try {
        const {
            codigo,        // obligatorio: identificador único del basurero
            nombre,        // opcional
            capacidad,     // opcional (decimal)
            ubicacion,     // opcional
            descripcion    // opcional
        } = req.body;

        if (!codigo) {
            return res.status(400).json({
                success: false,
                error: 'El campo "codigo" es obligatorio'
            });
        }

        // ¿Ya existe un basurero con ese código?
        const [existe] = await poolPromise.execute(
            'SELECT id_basurero FROM basureros WHERE codigo = ? LIMIT 1',
            [codigo]
        );

        let idBasurero;

        if (existe && existe.length > 0) {
            // Si existe, actualizamos datos básicos (solo si vienen en el body)
            idBasurero = existe[0].id_basurero;

            await poolPromise.execute(
                `UPDATE basureros
                 SET 
                    nombre      = COALESCE(?, nombre),
                    capacidad   = COALESCE(?, capacidad),
                    ubicacion   = COALESCE(?, ubicacion),
                    descripcion = COALESCE(?, descripcion)
                 WHERE id_basurero = ?`,
                [
                    nombre || null,
                    capacidad || null,
                    ubicacion || null,
                    descripcion || null,
                    idBasurero
                ]
            );

            return res.json({
                success: true,
                message: 'Basurero actualizado correctamente',
                data: { id_basurero: idBasurero, codigo }
            });

        } else {
            // Si no existe, lo creamos
            const [result] = await poolPromise.execute(
                `INSERT INTO basureros (
                    nombre,
                    codigo,
                    capacidad,
                    ubicacion,
                    descripcion,
                    id_estado,
                    fecha_instalacion
                ) VALUES (?, ?, ?, ?, ?, 1, NOW())`,
                [
                    nombre || `Basurero ${codigo}`,
                    codigo,
                    capacidad || 0,
                    ubicacion || null,
                    descripcion || null
                ]
            );

            idBasurero = result.insertId;

            return res.status(201).json({
                success: true,
                message: 'Basurero registrado correctamente',
                data: { id_basurero: idBasurero, codigo }
            });
        }

    } catch (error) {
        console.error('Error en /api/basureros/registro:', error);
        return res.status(500).json({
            success: false,
            error: 'Error al registrar basurero',
            details: error.message
        });
    }
});

// ==================== CONEXIONES A BASUREROS ====================

app.post('/api/basureros/conexion', async (req, res) => {
    try {
        const {
            id_usuario,
            id_basurero,
            tipo_conexion,
            ip_cliente,
            dispositivo,
            latitud,
            longitud
        } = req.body;

        // Validaciones básicas
        if (!id_usuario || !id_basurero) {
            return res.status(400).json({
                success: false,
                error: 'id_usuario y id_basurero son obligatorios'
            });
        }

        const tipoValido = ['consulta', 'apertura', 'deposito', 'otro'];
        const tipo = (tipo_conexion || 'consulta').toLowerCase();

        if (!tipoValido.includes(tipo)) {
            return res.status(400).json({
                success: false,
                error: 'tipo_conexion debe ser: consulta, apertura, deposito u otro'
            });
        }

        console.log('Registrando conexión:', {
        id_usuario,
        id_basurero,
        tipo,
        ip_cliente,
        dispositivo,
        latitud,
        longitud
        });


        const [result] = await poolPromise.execute(
            `INSERT INTO basureros_conexiones (
                id_basurero,
                id_usuario,
                tipo_conexion,
                ip_cliente,
                dispositivo,
                latitud,
                longitud
            ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                id_basurero,
                id_usuario,
                tipo,
                ip_cliente || null,
                dispositivo || null,
                latitud || null,
                longitud || null
            ]
        );

        return res.status(201).json({
            success: true,
            message: 'Conexión registrada correctamente',
            data: {
                id_conexion: result.insertId,
                id_basurero,
                id_usuario,
                tipo_conexion: tipo
            }
        });

    } catch (error) {
        console.error('Error en /api/basureros/conexion:', error);
        return res.status(500).json({
            success: false,
            error: 'Error al registrar conexión',
            details: error.message
        });
    }
});

// ==================== Obtener basurero coenctado a esp ====================


// Obtener basurero por código
app.get('/api/basureros/codigo/:codigo', async (req, res) => {
  try {
    const { codigo } = req.params;

    const [rows] = await poolPromise.execute(
      'SELECT id_basurero, nombre, codigo, capacidad, ubicacion, descripcion FROM basureros WHERE codigo = ? LIMIT 1',
      [codigo]
    );

    if (!rows || rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Basurero no encontrado'
      });
    }

    res.json({
      success: true,
      data: rows[0]
    });
  } catch (error) {
    console.error('Error en /api/basureros/codigo/:codigo', error);
    res.status(500).json({
      success: false,
      error: 'Error al buscar basurero'
    });
  }
});

// ==================== REGISTRAR CONEXIÓN AL BASURERO ====================
app.post('/api/basureros/:codigo/registrar-conexion', async (req, res) => {
    try {
        const { codigo } = req.params;
        const {
            id_usuario,
            tipo_conexion,
            ip_cliente,
            dispositivo,
            latitud,
            longitud
        } = req.body;

        console.log(`📱 Registrando conexión al basurero: ${codigo}`);

        // Buscar basurero por código
        const [basurero] = await poolPromise.execute(
            'SELECT id_basurero, nombre FROM basureros WHERE codigo = ?',
            [codigo]
        );

        if (basurero.length === 0) {
            return res.status(404).json({
                success: false,
                error: 'Basurero no encontrado'
            });
        }

        const id_basurero = basurero[0].id_basurero;

        // Registrar conexión
        const [result] = await poolPromise.execute(
            `INSERT INTO basureros_conexiones 
             (id_basurero, id_usuario, tipo_conexion, ip_cliente, dispositivo, latitud, longitud)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                id_basurero,
                id_usuario || null,
                tipo_conexion || 'consulta',
                ip_cliente || null,
                dispositivo || null,
                latitud || null,
                longitud || null
            ]
        );

        console.log(`✅ Conexión registrada con ID: ${result.insertId}`);

        // Actualizar última fecha de acceso en usuarios_basureros
        if (id_usuario) {
            await poolPromise.execute(
                `INSERT INTO usuarios_basureros (id_usuario, id_basurero, fecha_acceso, id_estado)
                 VALUES (?, ?, NOW(), 1)
                 ON DUPLICATE KEY UPDATE fecha_acceso = NOW()`,
                [id_usuario, id_basurero]
            );
        }

        res.json({
            success: true,
            message: 'Conexión registrada exitosamente',
            data: {
                id_conexion: result.insertId,
                id_basurero: id_basurero,
                nombre_basurero: basurero[0].nombre,
                codigo: codigo
            }
        });
    } catch (error) {
        console.error('❌ Error al registrar conexión:', error);
        res.status(500).json({
            success: false,
            error: 'Error al registrar conexión',
            details: error.message
        });
    }
});

// ==================== OBTENER HISTORIAL DE CONEXIONES ====================
app.get('/api/basureros/:codigo/conexiones', async (req, res) => {
    try {
        const { codigo } = req.params;
        const { limit = 50 } = req.query;

        const [conexiones] = await poolPromise.execute(
            `SELECT 
                bc.id_conexion,
                bc.tipo_conexion,
                bc.ip_cliente,
                bc.dispositivo,
                bc.fecha_conexion,
                u.nombre,
                u.apellido
            FROM basureros_conexiones bc
            LEFT JOIN usuarios u ON bc.id_usuario = u.id_usuario
            WHERE bc.id_basurero = (SELECT id_basurero FROM basureros WHERE codigo = ?)
            ORDER BY bc.fecha_conexion DESC
            LIMIT ?`,
            [codigo, parseInt(limit)]
        );

        res.json({
            success: true,
            total: conexiones.length,
            data: conexiones
        });
    } catch (error) {
        console.error('❌ Error al obtener conexiones:', error);
        res.status(500).json({
            success: false,
            error: 'Error al obtener historial de conexiones'
        });
    }
});




// ==================== DETECCIONES ====================

// ==================== DETECCIONES ====================

// Guardar una nueva detección
app.post('/api/detecciones', async (req, res) => {
  try {
    const {
      id_usuario,
      id_basurero,
      id_categoria,
      nombre_objeto,
      confianza,
      peso_gramos,
      puntos_ganados,
      foto,
      latitud,
      longitud
    } = req.body;

    // Validaciones básicas
    if (!id_usuario) {
      return res.status(400).json({
        success: false,
        error: 'id_usuario es obligatorio'
      });
    }

    if (!id_categoria) {
      return res.status(400).json({
        success: false,
        error: 'id_categoria es obligatoria'
      });
    }

    if (!nombre_objeto) {
      return res.status(400).json({
        success: false,
        error: 'nombre_objeto es obligatorio'
      });
    }

    // Puntos por defecto si no viene en el body
    const puntos = puntos_ganados ?? 10;

    console.log('💾 Guardando detección...', {
      id_usuario,
      id_basurero,
      id_categoria,
      nombre_objeto,
      confianza,
      peso_gramos,
      puntos_ganados: puntos,
      latitud,
      longitud
    });

    // Insertar detección en la tabla
    const [result] = await poolPromise.execute(
      `INSERT INTO detecciones (
        id_usuario,
        id_basurero,
        id_categoria,
        nombre_objeto,
        confianza,
        peso_gramos,
        puntos_ganados,
        foto,
        latitud,
        longitud
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id_usuario,
        id_basurero || null,
        id_categoria,
        nombre_objeto,
        confianza ?? null,
        peso_gramos ?? null,
        puntos,
        foto || null,
        latitud ?? null,
        longitud ?? null
      ]
    );

    // Obtener la detección insertada (para devolver fecha_deteccion)
    const [rows] = await poolPromise.execute(
      `SELECT id_deteccion, fecha_deteccion
       FROM detecciones
       WHERE id_deteccion = ?`,
      [result.insertId]
    );

    const insercion = rows[0];

    return res.status(201).json({
      success: true,
      message: 'Detección guardada exitosamente',
      data: {
        id_deteccion: insercion.id_deteccion,
        fecha_deteccion: insercion.fecha_deteccion,
        puntos_ganados: puntos
      }
    });

  } catch (error) {
    console.error('❌ Error al guardar detección:', error);
    return res.status(500).json({
      success: false,
      error: 'Error al guardar detección',
      details: error.message
    });
  }
});


// Obtener historial de detecciones de un usuario
app.get('/api/detecciones/usuario/:id_usuario', async (req, res) => {
    try {
        const { id_usuario } = req.params;
        const { tipo, limit = 50 } = req.query;

        let query = `
            SELECT 
                id_deteccion,
                tipo_residuo,
                nombre_objeto,
                confianza,
                peso_gramos,
                puntos_ganados,
                foto,
                latitud,
                longitud,
                fecha_deteccion
            FROM detecciones
            WHERE id_usuario = ?
        `;

        const params = [id_usuario];

        // Si hay filtro por tipo
        if (tipo && ['organico', 'inorganico', 'reciclable'].includes(tipo.toLowerCase())) {
            query += ` AND tipo_residuo = ?`;
            params.push(tipo.toLowerCase());
        }

        query += ` ORDER BY fecha_deteccion DESC LIMIT ?`;
        params.push(parseInt(limit));

        const [datos] = await poolPromise.execute(query, params);

        res.json({
            success: true,
            total: datos.length,
            data: datos
        });
    } catch (error) {
        console.error('Error al obtener detecciones:', error);
        res.status(500).json({
            success: false,
            error: 'Error al obtener historial de detecciones',
            details: error.message
        });
    }
});

// ==================== ESTADÍSTICAS ====================

// Obtener estadísticas generales de un usuario
app.get('/api/detecciones/estadisticas/:id_usuario', async (req, res) => {
    try {
        const { id_usuario } = req.params;

        // Total de detecciones
        const [totalResult] = await poolPromise.execute(
            'SELECT COUNT(*) as total FROM detecciones WHERE id_usuario = ?',
            [id_usuario]
        );

        // Detecciones por tipo
        const [porTipo] = await poolPromise.execute(
            `SELECT 
                tipo_residuo,
                COUNT(*) as cantidad,
                SUM(puntos_ganados) as puntos_totales
            FROM detecciones
            WHERE id_usuario = ?
            GROUP BY tipo_residuo`,
            [id_usuario]
        );

        // Puntos totales
        const [puntosResult] = await poolPromise.execute(
            'SELECT SUM(puntos_ganados) as puntos_totales FROM detecciones WHERE id_usuario = ?',
            [id_usuario]
        );

        // Promedio de confianza
        const [confianzaResult] = await poolPromise.execute(
            'SELECT AVG(confianza) as confianza_promedio FROM detecciones WHERE id_usuario = ?',
            [id_usuario]
        );

        res.json({
            success: true,
            data: {
                total_detecciones: totalResult[0].total,
                puntos_totales: puntosResult[0].puntos_totales || 0,
                confianza_promedio: Math.round(confianzaResult[0].confianza_promedio || 0),
                por_tipo: porTipo
            }
        });
    } catch (error) {
        console.error('Error al obtener estadísticas:', error);
        res.status(500).json({
            success: false,
            error: 'Error al obtener estadísticas',
            details: error.message
        });
    }
});

// ==================== USUARIOS ====================

// ==================== USUARIOS ====================

// Obtener todos los usuarios
app.get('/api/usuarios', async (req, res) => {
    try {
        const [usuarios] = await poolPromise.execute(
            `SELECT 
                id_usuario, 
                nombre, 
                apellido, 
                correo, 
                id_rol, 
                id_estado, 
                fecha_creacion
             FROM usuarios
             ORDER BY fecha_creacion DESC`
        );

        res.json({
            success: true,
            total: usuarios.length,
            data: usuarios
        });
    } catch (error) {
        console.error('Error al obtener usuarios:', error);
        res.status(500).json({
            success: false,
            error: 'Error al obtener usuarios',
            details: error.message
        });
    }
});


// ==================== HEALTH CHECK ====================
app.get('/api/health', async (req, res) => {
    try {
        const [result] = await poolPromise.execute('SELECT 1 + 1 AS resultado');
        res.json({
            success: true,
            message: 'Conexión a MySQL exitosa',
            database: 'db_separapp',
            test: result[0].resultado
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'Error de conexión a MySQL',
            details: error.message
        });
    }
});

// ==================== PANEL DE ESTADO ====================

// ==================== ESTADÍSTICAS DEL BASURERO ====================

// Obtener estadísticas de un basurero específico
app.get('/api/basureros/:id_basurero/estadisticas', async (req, res) => {
    try {
        const { id_basurero } = req.params;

        console.log(`📊 Obteniendo estadísticas del basurero ${id_basurero}`);

        // Obtener información básica del basurero
        const [basurero] = await poolPromise.execute(
            `SELECT 
                id_basurero,
                nombre,
                codigo,
                capacidad,
                ubicacion,
                id_estado
            FROM basureros
            WHERE id_basurero = ?
            LIMIT 1`,
            [id_basurero]
        );

        if (!basurero || basurero.length === 0) {
            return res.status(404).json({
                success: false,
                error: 'Basurero no encontrado'
            });
        }

        // Obtener total de detecciones en este basurero por categoría
        const [deteccionesPorCategoria] = await poolPromise.execute(
            `SELECT 
                c.id_categoria,
                c.nombre as categoria_nombre,
                COUNT(d.id_deteccion) as total_detecciones,
                COALESCE(SUM(d.peso_gramos), 0) as peso_total_gramos
            FROM categorias c
            LEFT JOIN detecciones d ON c.id_categoria = d.id_categoria 
                AND d.id_basurero = ?
            WHERE c.id_categoria IN (1, 2, 3, 4)
            GROUP BY c.id_categoria, c.nombre
            ORDER BY c.id_categoria`,
            [id_basurero]
        );

        // Calcular porcentaje de llenado por categoría (simulado por ahora)
        const capacidadTotal = basurero[0].capacidad || 1000; // kg
        const capacidadPorCategoria = capacidadTotal / 3; // Dividido en 3 compartimentos

        const estadisticas = deteccionesPorCategoria.map(cat => {
            const pesoKg = cat.peso_total_gramos / 1000;
            const porcentajeLlenado = Math.min(
                Math.round((pesoKg / capacidadPorCategoria) * 100),
                100
            );

            return {
                id_categoria: cat.id_categoria,
                nombre: cat.categoria_nombre,
                total_detecciones: cat.total_detecciones,
                peso_kg: Math.round(pesoKg * 100) / 100,
                porcentaje_llenado: porcentajeLlenado
            };
        });

        // Última detección en este basurero
        const [ultimaDeteccion] = await poolPromise.execute(
            `SELECT 
                d.nombre_objeto,
                c.nombre as categoria_nombre,
                d.confianza,
                d.fecha_deteccion,
                u.nombre as usuario_nombre
            FROM detecciones d
            LEFT JOIN categorias c ON d.id_categoria = c.id_categoria
            LEFT JOIN usuarios u ON d.id_usuario = u.id_usuario
            WHERE d.id_basurero = ?
            ORDER BY d.fecha_deteccion DESC
            LIMIT 1`,
            [id_basurero]
        );

        res.json({
            success: true,
            data: {
                basurero: basurero[0],
                estadisticas: estadisticas,
                ultima_deteccion: ultimaDeteccion[0] || null,
                capacidad_total_kg: capacidadTotal,
                peso_total_kg: Math.round(
                    deteccionesPorCategoria.reduce((sum, cat) => 
                        sum + (cat.peso_total_gramos / 1000), 0
                    ) * 100
                ) / 100
            }
        });

    } catch (error) {
        console.error('❌ Error al obtener estadísticas del basurero:', error);
        res.status(500).json({
            success: false,
            error: 'Error al obtener estadísticas del basurero',
            details: error.message
        });
    }
});

// ==================== PANEL COMBINADO (USUARIO + BASURERO) ====================

app.get('/api/panel/combinado/:id_usuario', async (req, res) => {
    try {
        const { id_usuario } = req.params;
        const { id_basurero } = req.query; // Opcional

        console.log(`📊 Panel combinado - Usuario: ${id_usuario}, Basurero: ${id_basurero || 'ninguno'}`);

        // 1. ESTADÍSTICAS DEL USUARIO (siempre)
        const [cantidadesUsuario] = await poolPromise.execute(
            `SELECT 
                CASE 
                    WHEN c.id_categoria = 1 THEN 'reciclable'
                    WHEN c.id_categoria = 2 THEN 'organico'
                    WHEN c.id_categoria = 3 THEN 'inorganico'
                    WHEN c.id_categoria = 4 THEN 'peligroso'
                    ELSE 'otro'
                END as tipo,
                COUNT(d.id_deteccion) as cantidad
            FROM categorias c
            LEFT JOIN detecciones d ON c.id_categoria = d.id_categoria 
                AND d.id_usuario = ?
            WHERE c.id_categoria IN (1, 2, 3, 4)
            GROUP BY c.id_categoria`,
            [id_usuario]
        );

        const [ultimaDeteccionUsuario] = await poolPromise.execute(
            `SELECT 
                c.nombre as categoria_nombre,
                d.nombre_objeto,
                d.confianza,
                d.fecha_deteccion
            FROM detecciones d
            LEFT JOIN categorias c ON d.id_categoria = c.id_categoria
            WHERE d.id_usuario = ?
            ORDER BY d.fecha_deteccion DESC
            LIMIT 1`,
            [id_usuario]
        );

        const [acierto] = await poolPromise.execute(
            `SELECT AVG(confianza) as porcentaje_acierto
             FROM detecciones
             WHERE id_usuario = ?`,
            [id_usuario]
        );

        const resultadoUsuario = {
            reciclable: 0,
            organico: 0,
            inorganico: 0,
            peligroso: 0
        };

        cantidadesUsuario.forEach(item => {
            if (item.tipo) {
                resultadoUsuario[item.tipo] = item.cantidad;
            }
        });

        const respuesta = {
            success: true,
            data: {
                usuario: {
                    cantidades: resultadoUsuario,
                    total: Object.values(resultadoUsuario).reduce((a, b) => a + b, 0),
                    ultima_deteccion: ultimaDeteccionUsuario[0] || null,
                    porcentaje_acierto: Math.round(acierto[0]?.porcentaje_acierto || 0)
                }
            }
        };

        // 2. ESTADÍSTICAS DEL BASURERO (solo si hay id_basurero)
        if (id_basurero) {
            const [basurero] = await poolPromise.execute(
                `SELECT nombre, codigo, capacidad FROM basureros WHERE id_basurero = ?`,
                [id_basurero]
            );

            if (basurero && basurero.length > 0) {
                const [deteccionesBasurero] = await poolPromise.execute(
                    `SELECT 
                        CASE 
                            WHEN c.id_categoria = 1 THEN 'reciclable'
                            WHEN c.id_categoria = 2 THEN 'organico'
                            WHEN c.id_categoria = 3 THEN 'inorganico'
                            ELSE 'otro'
                        END as tipo,
                        COUNT(d.id_deteccion) as total,
                        COALESCE(SUM(d.peso_gramos), 0) as peso_gramos
                    FROM categorias c
                    LEFT JOIN detecciones d ON c.id_categoria = d.id_categoria 
                        AND d.id_basurero = ?
                    WHERE c.id_categoria IN (1, 2, 3)
                    GROUP BY c.id_categoria`,
                    [id_basurero]
                );

                const capacidad = basurero[0].capacidad || 1000;
                const capacidadPorCompartimento = capacidad / 3;

                const llenadoBasurero = {
                    reciclable: 0,
                    organico: 0,
                    inorganico: 0
                };

                deteccionesBasurero.forEach(det => {
                    if (det.tipo) {
                        const pesoKg = det.peso_gramos / 1000;
                        const porcentaje = Math.min(
                            Math.round((pesoKg / capacidadPorCompartimento) * 100),
                            100
                        );
                        llenadoBasurero[det.tipo] = porcentaje;
                    }
                });

                respuesta.data.basurero = {
                    nombre: basurero[0].nombre,
                    codigo: basurero[0].codigo,
                    llenado: llenadoBasurero,
                    capacidad_total: capacidad,
                    estado: 'Operativo'
                };
            }
        }

        console.log('✅ Respuesta enviada:', JSON.stringify(respuesta, null, 2));
        res.json(respuesta);

    } catch (error) {
        console.error('❌ Error en panel combinado:', error);
        res.status(500).json({
            success: false,
            error: 'Error al obtener panel combinado',
            details: error.message
        });
    }
});

// ==================== OBTENER LLENADO ACTUAL DEL BASURERO ====================

app.get('/api/basureros/:id_basurero/llenado', async (req, res) => {
    try {
        const { id_basurero } = req.params;

        console.log(`📊 Obteniendo llenado del basurero ${id_basurero}`);

        // 1. Obtener capacidad del basurero
        const [basurero] = await poolPromise.execute(
            `SELECT capacidad FROM basureros WHERE id_basurero = ? LIMIT 1`,
            [id_basurero]
        );

        if (!basurero || basurero.length === 0) {
            return res.status(404).json({
                success: false,
                error: 'Basurero no encontrado'
            });
        }

        const capacidadTotal = basurero[0].capacidad || 1000; // kg
        const capacidadPorCompartimento = capacidadTotal / 3; // 3 compartimentos

        // 2. Obtener peso acumulado por categoría desde el último vaciado
        // (por ahora sin tabla de vaciados, calculamos el total)
        const [pesos] = await poolPromise.execute(
            `SELECT 
                CASE 
                    WHEN c.id_categoria = 1 THEN 'reciclable'
                    WHEN c.id_categoria = 2 THEN 'organico'
                    WHEN c.id_categoria = 3 THEN 'inorganico'
                    ELSE 'otro'
                END as tipo,
                COALESCE(SUM(d.peso_gramos), 0) as peso_total_gramos
            FROM categorias c
            LEFT JOIN detecciones d ON c.id_categoria = d.id_categoria 
                AND d.id_basurero = ?
            WHERE c.id_categoria IN (1, 2, 3)
            GROUP BY c.id_categoria`,
            [id_basurero]
        );

        // 3. Calcular porcentajes de llenado
        const llenado = {
            reciclable: 0,
            organico: 0,
            inorganico: 0
        };

        pesos.forEach(item => {
            if (item.tipo) {
                const pesoKg = item.peso_total_gramos / 1000;
                const porcentaje = Math.min(
                    Math.round((pesoKg / capacidadPorCompartimento) * 100),
                    100
                );
                llenado[item.tipo] = porcentaje;
            }
        });

        // 4. Calcular peso total
        const pesoTotalKg = pesos.reduce((sum, item) => 
            sum + (item.peso_total_gramos / 1000), 0
        );

        res.json({
            success: true,
            data: {
                id_basurero: parseInt(id_basurero),
                capacidad_total_kg: capacidadTotal,
                peso_actual_kg: Math.round(pesoTotalKg * 100) / 100,
                porcentaje_total: Math.min(
                    Math.round((pesoTotalKg / capacidadTotal) * 100),
                    100
                ),
                llenado: llenado,
                estado: pesoTotalKg >= (capacidadTotal * 0.9) ? 'Crítico' : 
                        pesoTotalKg >= (capacidadTotal * 0.7) ? 'Alto' : 
                        pesoTotalKg >= (capacidadTotal * 0.4) ? 'Medio' : 'Bajo'
            }
        });

    } catch (error) {
        console.error('❌ Error al obtener llenado del basurero:', error);
        res.status(500).json({
            success: false,
            error: 'Error al obtener llenado del basurero',
            details: error.message
        });
    }
});



// Obtener datos para el panel de estado
app.get('/api/panel/estado/:id_usuario', async (req, res) => {
    try {
        const { id_usuario } = req.params;

        // Obtener cantidades por tipo
        const [cantidades] = await poolPromise.execute(
            `SELECT 
                tipo_residuo,
                COUNT(*) as cantidad
            FROM detecciones
            WHERE id_usuario = ?
            GROUP BY tipo_residuo`,
            [id_usuario]
        );

        // Obtener última detección
        const [ultimaDeteccion] = await poolPromise.execute(
            `SELECT 
                tipo_residuo,
                nombre_objeto,
                fecha_deteccion
            FROM detecciones
            WHERE id_usuario = ?
            ORDER BY fecha_deteccion DESC
            LIMIT 1`,
            [id_usuario]
        );

        // Obtener porcentaje de acierto (promedio de confianza)
        const [acierto] = await poolPromise.execute(
            `SELECT 
                AVG(confianza) as porcentaje_acierto
            FROM detecciones
            WHERE id_usuario = ?`,
            [id_usuario]
        );

        // Formatear respuesta
        const resultado = {
            organico: 0,
            inorganico: 0,
            reciclable: 0
        };

        cantidades.forEach(item => {
            resultado[item.tipo_residuo] = item.cantidad;
        });

        res.json({
            success: true,
            data: {
                cantidades: resultado,
                ultima_accion: ultimaDeteccion[0] || null,
                porcentaje_acierto: Math.round(acierto[0]?.porcentaje_acierto || 0)
            }
        });
    } catch (error) {
        console.error('Error al obtener panel de estado:', error);
        res.status(500).json({
            success: false,
            error: 'Error al obtener panel de estado',
            details: error.message
        });
    }
});

// ==================== HISTORIAL DETALLADO ====================

// Obtener historial agrupado por tipo con estadísticas
// ==================== HISTORIAL DETALLADO ====================
// ==================== HISTORIAL DETALLADO ====================

// Obtener historial agrupado por tipo con estadísticas
app.get('/api/historial/resumen/:id_usuario', async (req, res) => {
    try {
        const { id_usuario } = req.params;

        console.log(`📊 Obteniendo resumen de historial para usuario ${id_usuario}`);

        // Obtener resumen por cada categoría
        const [resumen] = await poolPromise.execute(
            `SELECT 
                c.id_categoria,
                CASE 
                    WHEN c.id_categoria = 1 THEN 'reciclable'
                    WHEN c.id_categoria = 2 THEN 'organico'
                    WHEN c.id_categoria = 3 THEN 'inorganico'
                    ELSE 'otro'
                END as tipo,
                COUNT(d.id_deteccion) as cantidad,
                AVG(d.confianza) as clasificacion_promedio,
                MAX(d.fecha_deteccion) as ultima_accion
            FROM categorias c
            LEFT JOIN detecciones d ON c.id_categoria = d.id_categoria 
                AND d.id_usuario = ?
            WHERE c.id_categoria IN (1, 2, 3)
            GROUP BY c.id_categoria, c.nombre
            ORDER BY c.id_categoria`,
            [id_usuario]
        );

        console.log('📋 Datos obtenidos:', resumen);

        // Formatear respuesta para cada tipo
        const resultado = {
            organico: {
                cantidad: 0,
                llenado: 'Vacío',
                clasificacion: 0,
                ultimaAccion: null
            },
            reciclable: {
                cantidad: 0,
                llenado: 'Vacío',
                clasificacion: 0,
                ultimaAccion: null
            },
            inorganico: {
                cantidad: 0,
                llenado: 'Vacío',
                clasificacion: 0,
                ultimaAccion: null
            }
        };

        // Mapear resultados
        resumen.forEach(item => {
            const tipo = item.tipo;
            if (tipo && resultado[tipo]) {
                resultado[tipo] = {
                    cantidad: item.cantidad || 0,
                    llenado: calcularLlenado(item.cantidad || 0),
                    clasificacion: Math.round(item.clasificacion_promedio || 0),
                    ultimaAccion: formatearHora(item.ultima_accion)
                };
            }
        });

        console.log('✅ Resumen generado:', resultado);

        res.json({
            success: true,
            data: resultado
        });
    } catch (error) {
        console.error('❌ Error al obtener resumen de historial:', error);
        res.status(500).json({
            success: false,
            error: 'Error al obtener resumen de historial',
            details: error.message
        });
    }
});

// Función auxiliar para calcular nivel de llenado
function calcularLlenado(cantidad) {
    if (cantidad === 0) return 'Vacío';
    if (cantidad < 10) return 'Bajo';
    if (cantidad < 20) return 'Medio';
    return 'Alto';
}

// Función auxiliar para formatear hora
function formatearHora(fecha) {
    if (!fecha) return null;
    try {
        const d = new Date(fecha);
        const horas = d.getHours().toString().padStart(2, '0');
        const minutos = d.getMinutes().toString().padStart(2, '0');
        const ampm = d.getHours() >= 12 ? 'PM' : 'AM';
        return `${horas}:${minutos} ${ampm}`;
    } catch (e) {
        return null;
    }
}

// Función auxiliar para calcular nivel de llenado
function calcularLlenado(cantidad) {
    if (cantidad === 0) return 'Vacío';
    if (cantidad < 10) return 'Bajo';
    if (cantidad < 20) return 'Medio';
    return 'Alto';
}

// Función auxiliar para formatear hora
function formatearHora(fecha) {
    if (!fecha) return null;
    const d = new Date(fecha);
    const horas = d.getHours().toString().padStart(2, '0');
    const minutos = d.getMinutes().toString().padStart(2, '0');
    const ampm = d.getHours() >= 12 ? 'PM' : 'AM';
    return `${horas}:${minutos} ${ampm}`;
}


// Función auxiliar para calcular nivel de llenado
function calcularLlenado(cantidad) {
    if (cantidad === 0) return 'Vacío';
    if (cantidad < 10) return 'Bajo';
    if (cantidad < 20) return 'Medio';
    return 'Alto';
}

// Función auxiliar para formatear hora
function formatearHora(fecha) {
    if (!fecha) return null;
    const d = new Date(fecha);
    const horas = d.getHours().toString().padStart(2, '0');
    const minutos = d.getMinutes().toString().padStart(2, '0');
    const ampm = d.getHours() >= 12 ? 'PM' : 'AM';
    return `${horas}:${minutos} ${ampm}`;
}

// ==================== DETECCIONES DE HOY ====================

// Obtener detecciones del día actual
app.get('/api/detecciones/hoy/:id_usuario', async (req, res) => {
    try {
        const { id_usuario } = req.params;

        const [result] = await poolPromise.execute(
            `SELECT 
                id_deteccion,
                tipo_residuo,
                nombre_objeto,
                confianza,
                puntos_ganados,
                fecha_deteccion
            FROM detecciones
            WHERE id_usuario = ?
            AND DATE(fecha_deteccion) = CURDATE()
            ORDER BY fecha_deteccion DESC`,
            [id_usuario]
        );

        res.json({
            success: true,
            total: result.length,
            data: result
        });
    } catch (error) {
        console.error('Error al obtener detecciones de hoy:', error);
        res.status(500).json({
            success: false,
            error: 'Error al obtener detecciones de hoy',
            details: error.message
        });
    }
});

// ==================== INICIAR SERVIDOR ====================
const server = app.listen(port, '0.0.0.0', () => {    console.log('\n========================================');
    console.log('API SEPARAPP - Sistema de Reciclaje');
    console.log('========================================');
    console.log(`📡 Servidor corriendo en: http://localhost:${port}`);
    console.log(`\nEndpoints disponibles:`);
    console.log(`   POST /api/login                              - Login de usuario`);
    console.log(`   GET  /api/health                             - Verificar conexión DB`);
    console.log(`   GET  /api/usuarios                           - Obtener todos los usuarios`);
    console.log(`   POST /api/detecciones                        - Guardar detección`);
    console.log(`   GET  /api/detecciones/usuario/:id            - Historial completo`);
    console.log(`   GET  /api/detecciones/estadisticas/:id       - Estadísticas de usuario`);
    console.log(`   GET  /api/panel/estado/:id                   - Panel de estado`);
    console.log(`   GET  /api/historial/resumen/:id              - Resumen para historial`);
    console.log(`   GET  /api/detecciones/hoy/:id                - Detecciones de hoy`);
    console.log('========================================\n');
});

// Manejo de cierre limpio
process.on('SIGINT', async () => {
    console.log('\n\nCerrando servidor...');
    try {
        await poolPromise.end();
        console.log('Conexión a MySQL cerrada');
        server.close(() => {
            console.log('Servidor cerrado correctamente');
            process.exit(0);
        });
    } catch (err) {
        console.error('Error al cerrar:', err);
        process.exit(1);
    }
});

process.on('SIGTERM', async () => {
    console.log('\n\nSeñal SIGTERM recibida, cerrando servidor...');
    try {
        await poolPromise.end();
        console.log(' Conexión a MySQL cerrada');
        server.close(() => {
            console.log('Servidor cerrado correctamente');
            process.exit(0);
        });
    } catch (err) {
        console.error('Error al cerrar:', err);
        process.exit(1);
    }
});

// ==================== HISTORIAL DEL BASURERO ====================

// Obtener historial de detecciones de un basurero específico
app.get('/api/basureros/:id_basurero/historial', async (req, res) => {
    try {
        const { id_basurero } = req.params;
        const { limit = 50 } = req.query;

        console.log(`📊 Obteniendo historial del basurero ${id_basurero}`);

        const [detecciones] = await poolPromise.execute(
            `SELECT 
                d.id_deteccion,
                d.nombre_objeto,
                d.confianza,
                d.peso_gramos,
                d.puntos_ganados,
                d.fecha_deteccion,
                c.nombre as categoria_nombre,
                c.id_categoria,
                u.nombre as usuario_nombre,
                u.apellido as usuario_apellido
            FROM detecciones d
            LEFT JOIN categorias c ON d.id_categoria = c.id_categoria
            LEFT JOIN usuarios u ON d.id_usuario = u.id_usuario
            WHERE d.id_basurero = ?
            ORDER BY d.fecha_deteccion DESC
            LIMIT ?`,
            [id_basurero, parseInt(limit)]
        );

        // Estadísticas rápidas
        const [stats] = await poolPromise.execute(
            `SELECT 
                COUNT(*) as total_detecciones,
                AVG(confianza) as confianza_promedio,
                SUM(puntos_ganados) as puntos_totales
            FROM detecciones
            WHERE id_basurero = ?`,
            [id_basurero]
        );

        res.json({
            success: true,
            total: detecciones.length,
            estadisticas: {
                total_detecciones: stats[0].total_detecciones || 0,
                confianza_promedio: Math.round(stats[0].confianza_promedio || 0),
                puntos_totales: stats[0].puntos_totales || 0
            },
            data: detecciones
        });

    } catch (error) {
        console.error('❌ Error al obtener historial del basurero:', error);
        res.status(500).json({
            success: false,
            error: 'Error al obtener historial del basurero'
        });
    }
});

// ==================== ESTADÍSTICAS DETALLADAS DEL USUARIO ====================

app.get('/api/usuarios/:id_usuario/estadisticas-detalladas', async (req, res) => {
    try {
        const { id_usuario } = req.params;

        console.log(`📊 Estadísticas detalladas del usuario ${id_usuario}`);

        // 1. Por categoría
        const [porCategoria] = await poolPromise.execute(
            `SELECT 
                c.id_categoria,
                c.nombre as categoria,
                COUNT(d.id_deteccion) as cantidad,
                AVG(d.confianza) as confianza_promedio,
                SUM(d.puntos_ganados) as puntos
            FROM categorias c
            LEFT JOIN detecciones d ON c.id_categoria = d.id_categoria 
                AND d.id_usuario = ?
            WHERE c.id_categoria IN (1, 2, 3)
            GROUP BY c.id_categoria, c.nombre`,
            [id_usuario]
        );

        // 2. Por día (últimos 7 días)
        const [porDia] = await poolPromise.execute(
            `SELECT 
                DATE(fecha_deteccion) as fecha,
                COUNT(*) as cantidad,
                SUM(puntos_ganados) as puntos
            FROM detecciones
            WHERE id_usuario = ?
            AND fecha_deteccion >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
            GROUP BY DATE(fecha_deteccion)
            ORDER BY fecha DESC`,
            [id_usuario]
        );

        // 3. Por semana (últimas 4 semanas)
        const [porSemana] = await poolPromise.execute(
            `SELECT 
                YEARWEEK(fecha_deteccion, 1) as semana,
                MIN(DATE(fecha_deteccion)) as inicio_semana,
                COUNT(*) as cantidad,
                SUM(puntos_ganados) as puntos
            FROM detecciones
            WHERE id_usuario = ?
            AND fecha_deteccion >= DATE_SUB(CURDATE(), INTERVAL 4 WEEK)
            GROUP BY YEARWEEK(fecha_deteccion, 1)
            ORDER BY semana DESC`,
            [id_usuario]
        );

        // 4. Totales generales
        const [totales] = await poolPromise.execute(
            `SELECT 
                COUNT(*) as total_clasificaciones,
                SUM(puntos_ganados) as puntos_totales,
                AVG(confianza) as confianza_promedio,
                MAX(fecha_deteccion) as ultima_deteccion
            FROM detecciones
            WHERE id_usuario = ?`,
            [id_usuario]
        );

        // 5. Racha actual (días consecutivos)
        const [racha] = await poolPromise.execute(
            `SELECT COUNT(DISTINCT DATE(fecha_deteccion)) as dias_activos
            FROM detecciones
            WHERE id_usuario = ?
            AND fecha_deteccion >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)`,
            [id_usuario]
        );

        res.json({
            success: true,
            data: {
                totales: {
                    clasificaciones: totales[0].total_clasificaciones || 0,
                    puntos: totales[0].puntos_totales || 0,
                    confianza_promedio: Math.round(totales[0].confianza_promedio || 0),
                    ultima_deteccion: totales[0].ultima_deteccion
                },
                por_categoria: porCategoria,
                por_dia: porDia,
                por_semana: porSemana,
                dias_activos_mes: racha[0].dias_activos || 0
            }
        });

    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({
            success: false,
            error: 'Error al obtener estadísticas'
        });
    }
});

// ==================== ESTADÍSTICAS DETALLADAS DEL BASURERO ====================

app.get('/api/basureros/:id_basurero/estadisticas-detalladas', async (req, res) => {
    try {
        const { id_basurero } = req.params;

        console.log(`📊 Estadísticas detalladas del basurero ${id_basurero}`);

        // Info del basurero
        const [basurero] = await poolPromise.execute(
            `SELECT nombre, codigo, capacidad, ubicacion FROM basureros WHERE id_basurero = ?`,
            [id_basurero]
        );

        if (!basurero || basurero.length === 0) {
            return res.status(404).json({ success: false, error: 'Basurero no encontrado' });
        }

        // Por categoría
        const [porCategoria] = await poolPromise.execute(
            `SELECT 
                c.id_categoria,
                c.nombre as categoria,
                COUNT(d.id_deteccion) as cantidad,
                COALESCE(SUM(d.peso_gramos), 0) as peso_total_gramos,
                AVG(d.confianza) as confianza_promedio
            FROM categorias c
            LEFT JOIN detecciones d ON c.id_categoria = d.id_categoria 
                AND d.id_basurero = ?
            WHERE c.id_categoria IN (1, 2, 3)
            GROUP BY c.id_categoria, c.nombre`,
            [id_basurero]
        );

        // Por día (últimos 7 días)
        const [porDia] = await poolPromise.execute(
            `SELECT 
                DATE(fecha_deteccion) as fecha,
                COUNT(*) as cantidad
            FROM detecciones
            WHERE id_basurero = ?
            AND fecha_deteccion >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
            GROUP BY DATE(fecha_deteccion)
            ORDER BY fecha DESC`,
            [id_basurero]
        );

        // Usuarios que han usado este basurero
        const [usuarios] = await poolPromise.execute(
            `SELECT 
                u.id_usuario,
                u.nombre,
                u.apellido,
                COUNT(d.id_deteccion) as clasificaciones
            FROM usuarios u
            INNER JOIN detecciones d ON u.id_usuario = d.id_usuario
            WHERE d.id_basurero = ?
            GROUP BY u.id_usuario, u.nombre, u.apellido
            ORDER BY clasificaciones DESC
            LIMIT 10`,
            [id_basurero]
        );

        // Totales
        const [totales] = await poolPromise.execute(
            `SELECT 
                COUNT(*) as total_detecciones,
                COUNT(DISTINCT id_usuario) as usuarios_unicos,
                AVG(confianza) as confianza_promedio
            FROM detecciones
            WHERE id_basurero = ?`,
            [id_basurero]
        );

        // Calcular llenado
        const capacidad = basurero[0].capacidad || 50;
        const capacidadPorCompartimento = capacidad / 3;

        const llenado = {
            reciclable: 0,
            organico: 0,
            inorganico: 0
        };

        porCategoria.forEach(cat => {
            const pesoKg = cat.peso_total_gramos / 1000;
            const porcentaje = Math.min(Math.round((pesoKg / capacidadPorCompartimento) * 100), 100);
            
            if (cat.id_categoria === 1) llenado.reciclable = porcentaje;
            if (cat.id_categoria === 2) llenado.organico = porcentaje;
            if (cat.id_categoria === 3) llenado.inorganico = porcentaje;
        });

        res.json({
            success: true,
            data: {
                basurero: basurero[0],
                totales: {
                    detecciones: totales[0].total_detecciones || 0,
                    usuarios_unicos: totales[0].usuarios_unicos || 0,
                    confianza_promedio: Math.round(totales[0].confianza_promedio || 0)
                },
                llenado: llenado,
                por_categoria: porCategoria,
                por_dia: porDia,
                top_usuarios: usuarios
            }
        });

    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({
            success: false,
            error: 'Error al obtener estadísticas del basurero'
        });
    }
});

// ==================== RANKING DE USUARIOS ====================

app.get('/api/ranking', async (req, res) => {
    try {
        const { limit = 10 } = req.query;

        const [ranking] = await poolPromise.execute(
            `SELECT 
                u.id_usuario,
                u.nombre,
                u.apellido,
                COUNT(d.id_deteccion) as clasificaciones,
                SUM(d.puntos_ganados) as puntos_totales,
                AVG(d.confianza) as confianza_promedio
            FROM usuarios u
            LEFT JOIN detecciones d ON u.id_usuario = d.id_usuario
            GROUP BY u.id_usuario, u.nombre, u.apellido
            HAVING clasificaciones > 0
            ORDER BY puntos_totales DESC
            LIMIT ?`,
            [parseInt(limit)]
        );

        res.json({
            success: true,
            total: ranking.length,
            data: ranking.map((user, index) => ({
                posicion: index + 1,
                ...user,
                confianza_promedio: Math.round(user.confianza_promedio || 0)
            }))
        });

    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({
            success: false,
            error: 'Error al obtener ranking'
        });
    }
});