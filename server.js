// server.js - Backend SeparAPP
const express = require('express');
const cors = require('cors');
const { poolPromise } = require('./config');
require('dotenv').config();

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

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

// Obtener todos los usuarios
app.get('/api/usuarios', async (req, res) => {
    try {
        const [usuarios] = await poolPromise.execute(
            `SELECT 
                id_usuario, nombre, apellido, correo, id_rol, id_estado, fecha_registro
            FROM usuarios
            ORDER BY fecha_registro DESC`
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
app.get('/api/historial/resumen/:id_usuario', async (req, res) => {
    try {
        const { id_usuario } = req.params;

        // Obtener resumen por cada tipo
        const [resumen] = await poolPromise.execute(
            `SELECT 
                tipo_residuo,
                COUNT(*) as cantidad,
                AVG(confianza) as clasificacion_promedio,
                MAX(fecha_deteccion) as ultima_accion
            FROM detecciones
            WHERE id_usuario = ?
            GROUP BY tipo_residuo`,
            [id_usuario]
        );

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

        resumen.forEach(item => {
            const tipo = item.tipo_residuo;
            resultado[tipo] = {
                cantidad: item.cantidad,
                llenado: calcularLlenado(item.cantidad),
                clasificacion: Math.round(item.clasificacion_promedio || 0),
                ultimaAccion: formatearHora(item.ultima_accion)
            };
        });

        res.json({
            success: true,
            data: resultado
        });
    } catch (error) {
        console.error('Error al obtener resumen de historial:', error);
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