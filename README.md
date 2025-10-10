# Microservicio de Autenticación

Microservicio completo y listo para producción de autenticación para plataforma de citas y servicios (barberías, salones, etc).

## 📋 Descripción

Este microservicio maneja toda la autenticación del sistema, permitiendo que otros microservicios deleguen la validación de usuarios y tokens. Utiliza JWT para autenticación stateless y PostgreSQL para persistencia de datos.

**Responsabilidades:**
- Autenticación de usuarios (login)
- Generación y validación de tokens JWT
- Renovación de tokens (refresh tokens)
- Logout y invalidación de sesiones
- Cambio de contraseña
- Validación de tokens para otros servicios

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────┐
│       Otros Microservicios              │
│    (Barbería, Usuario, Citas, etc)     │
└─────────────┬───────────────────────────┘
              │
              │ HTTP/REST
              ▼
┌─────────────────────────────────────────┐
│   API Gateway / Load Balancer           │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│     Auth Microservice (Node.js)         │
│  ┌─────────────────────────────────┐    │
│  │      Express Routes             │    │
│  │  /login /refresh /validate      │    │
│  │  /logout /change-password       │    │
│  └────────────┬────────────────────┘    │
│               │                         │
│  ┌────────────▼────────────┐            │
│  │   JWT & Seguridad       │            │
│  │  bcrypt, JWT, helmet    │            │
│  └────────────┬────────────┘            │
└─────────────┬─────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│      PostgreSQL Database                │
│  ┌────────────────────────────────┐    │
│  │  users table                   │    │
│  │  - id, email, password_hash    │    │
│  │  - refresh_token, timestamps   │    │
│  └────────────────────────────────┘    │
└─────────────────────────────────────────┘
```

## 🛠️ Stack Tecnológico

| Componente | Tecnología | Razón |
|-----------|-----------|-------|
| **Runtime** | Node.js 18+ | Rápido, ligero, escalable |
| **Framework** | Express.js | Simple, estándar en microservicios |
| **BD** | PostgreSQL | Transaccional, segura, confiable |
| **Autenticación** | JWT + bcrypt | Stateless, escalable, seguro |
| **Comunicación** | REST API | Estándar, interoperable |
| **Containerización** | Docker | Consistencia entre ambientes |
| **Orquestación** | Docker Compose | Desarrollo local completo |

## 📦 Instalación

### Requisitos previos

- Node.js 18+ 
- PostgreSQL 12+
- Docker y Docker Compose (opcional)
- npm o yarn

### Pasos

1. **Clonar o descargar el proyecto:**
```bash
cd auth-microservice
```

2. **Instalar dependencias:**
```bash
npm install
```

3. **Configurar variables de entorno (.env):**
```env
# Base de Datos
DB_HOST=localhost
DB_PORT=5432
DB_NAME=auth_service
DB_USER=postgres
DB_PASSWORD=yourpassword

# JWT
JWT_SECRET=your_super_secret_jwt_key_change_this
JWT_REFRESH_SECRET=your_refresh_secret_key

# Tokens
ACCESS_TOKEN_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=7d

# Servidor
PORT=3001
NODE_ENV=development
```

⚠️ **IMPORTANTE:** Cambia los secrets en producción con valores seguros y únicos.

4. **Crear la base de datos:**

Conectarse a PostgreSQL y ejecutar:

```sql
CREATE DATABASE auth_service;
```

Luego ejecutar el schema:

```bash
psql -U postgres -d auth_service -f database/schema.sql
```

O simplemente ejecutar este SQL:

```sql
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  refresh_token TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email);
```

5. **Iniciar el servidor:**

**Desarrollo (con auto-reload):**
```bash
npm run dev
```

**Producción:**
```bash
npm start
```

El servidor estará disponible en `http://localhost:3001`

## 🐳 Ejecución con Docker

**Opción 1: Docker Compose (recomendado para desarrollo)**

```bash
docker-compose up
```

Esto levanta automáticamente PostgreSQL y el microservicio.

**Opción 2: Docker individual**

```bash
# Construir imagen
docker build -t auth-microservice .

# Ejecutar contenedor
docker run -p 3001:3001 --env-file .env auth-microservice
```

## 📡 Endpoints API

### 1. Login
**Descripción:** Autentica un usuario y retorna tokens

**Endpoint:** `POST /api/auth/login`

**Body:**
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Respuesta exitosa (200):**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "email": "user@example.com"
  }
}
```

**Error (401):**
```json
{
  "error": "Credenciales inválidas"
}
```

---

### 2. Refresh Token
**Descripción:** Genera un nuevo access token usando un refresh token válido

**Endpoint:** `POST /api/auth/refresh`

**Body:**
```json
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Respuesta exitosa (200):**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

### 3. Validar Token
**Descripción:** Verifica si un token es válido. Otros microservicios usan este endpoint

**Endpoint:** `POST /api/auth/validate`

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Respuesta exitosa (200):**
```json
{
  "valid": true,
  "user": {
    "userId": 1,
    "email": "user@example.com"
  }
}
```

**Error (403):**
```json
{
  "error": "Token inválido o expirado"
}
```

---

### 4. Logout
**Descripción:** Invalida la sesión del usuario eliminando su refresh token

**Endpoint:** `POST /api/auth/logout`

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Respuesta exitosa (200):**
```json
{
  "message": "Logout exitoso"
}
```

---

### 5. Cambiar Contraseña
**Descripción:** Permite al usuario cambiar su contraseña

**Endpoint:** `POST /api/auth/change-password`

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Body:**
```json
{
  "oldPassword": "oldpassword123",
  "newPassword": "newpassword456"
}
```

**Respuesta exitosa (200):**
```json
{
  "message": "Contraseña actualizada exitosamente"
}
```

---

### 6. Health Check
**Descripción:** Verifica el estado del servicio

**Endpoint:** `GET /health`

**Respuesta (200):**
```json
{
  "status": "OK",
  "timestamp": "2024-10-10T15:30:45.123Z"
}
```

## 💻 Ejemplos de Uso

### Desde JavaScript/Node.js

```javascript
// 1. Login
async function login() {
  const response = await fetch('http://localhost:3001/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'user@example.com',
      password: 'password123'
    })
  });

  const data = await response.json();
  const { accessToken, refreshToken } = data;
  
  // Guardar tokens (en el frontend, usar localStorage o sessionStorage)
  localStorage.setItem('accessToken', accessToken);
  localStorage.setItem('refreshToken', refreshToken);
}

// 2. Usar token en otros servicios
async function callProtectedService(accessToken) {
  const response = await fetch('http://localhost:3001/api/auth/validate', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`
    }
  });

  return await response.json();
}

// 3. Renovar token
async function refreshAccessToken() {
  const refreshToken = localStorage.getItem('refreshToken');
  const response = await fetch('http://localhost:3001/api/auth/refresh', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refreshToken })
  });

  const { accessToken } = await response.json();
  localStorage.setItem('accessToken', accessToken);
}
```

### Desde otro Microservicio (Express)

```javascript
const express = require('express');
const app = express();

// Middleware para validar tokens con el servicio de auth
async function validateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  try {
    const response = await fetch('http://auth-service:3001/api/auth/validate', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (!response.ok) {
      return res.status(403).json({ error: 'Token inválido' });
    }

    const data = await response.json();
    req.user = data.user;
    next();
  } catch (err) {
    res.status(500).json({ error: 'Error validando token' });
  }
}

// Usar el middleware
app.get('/api/barbershop/appointments', validateToken, (req, res) => {
  res.json({ 
    message: 'Citas del usuario',
    userId: req.user.userId 
  });
});
```

### Con cURL

```bash
# Login
curl -X POST http://localhost:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}'

# Validar token
curl -X POST http://localhost:3001/api/auth/validate \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Health check
curl http://localhost:3001/health
```

## 🔐 Flujo de Autenticación

```
1. Usuario envía credenciales
   POST /api/auth/login
        ↓
2. Servidor valida credenciales contra BD
        ↓
3. Si son válidas, genera JWT tokens
   - Access Token (válido 15 min)
   - Refresh Token (válido 7 días, almacenado en BD)
        ↓
4. Cliente recibe tokens y los almacena
        ↓
5. Cliente envía requests con Access Token en header
   Authorization: Bearer ACCESS_TOKEN
        ↓
6. Otros microservicios validan token con este servicio
   POST /api/auth/validate
        ↓
7. Si token expira, cliente usa Refresh Token para obtener uno nuevo
   POST /api/auth/refresh
        ↓
8. Usuario hace logout, refresh token se invalida en BD
```

## 🧪 Testing

Ejecutar tests unitarios:

```bash
npm test
```

Tests incluidos:
- Login con credenciales válidas
- Login con credenciales inválidas
- Validación de tokens
- Refresh de tokens
- Health check

## 📊 Estructura de Archivos

```
auth-microservice/
├── server.js                 # Punto de entrada
├── config/
│   ├── database.js          # Conexión PostgreSQL
│   └── jwt.js               # Funciones JWT
├── middleware/
│   └── auth.js              # Middleware de autenticación
├── routes/
│   └── auth.js              # Rutas de API
├── database/
│   └── schema.sql           # Schema de BD
├── __tests__/
│   └── auth.test.js         # Tests
├── .env.example             # Variables de ejemplo
├── .dockerignore
├── Dockerfile               # Imagen Docker
├── docker-compose.yml       # Composición de servicios
├── package.json
└── README.md
```

## 🚨 Seguridad

### Mejores prácticas implementadas:

- ✅ **Contraseñas hasheadas** con bcrypt (10 salts)
- ✅ **JWT con expiración** (access: 15 min, refresh: 7 días)
- ✅ **Refresh tokens almacenados en BD** para invalidación
- ✅ **Helmet.js** para headers de seguridad
- ✅ **CORS configurado** para orígenes específicos
- ✅ **Validación de entrada** con express-validator
- ✅ **Secrets en variables de entorno** (nunca hardcodeados)

### Para producción:

1. Usa HTTPS siempre
2. Cambia JWT_SECRET y JWT_REFRESH_SECRET con valores seguros
3. Implementa rate limiting
4. Agrega logging y monitoreo
5. Usa un servicio de secretos (Vault, AWS Secrets Manager)
6. Habilita CORS solo para dominios autorizados
7. Implementa 2FA si es necesario

## 📈 Escalabilidad

Este microservicio está diseñado para escalar:

- **Stateless:** No mantiene sesiones, usa JWT
- **BD dedicada:** PostgreSQL escalable independientemente
- **Contenedorizado:** Fácil de replicar con Kubernetes
- **Comunicación síncrona:** API REST simple
- **Monitorable:** Endpoint /health para health checks

Para producción:

```bash
# Con Kubernetes
kubectl create deployment auth-microservice --image=auth-microservice:latest
kubectl scale deployment auth-microservice --replicas=3

# Con Docker Swarm
docker service create --replicas 3 auth-microservice
```

## 🤝 Integración con otros Microservicios

### Patrón recomendado:

```
[Usuario] → [Frontend] → [API Gateway] → [Auth Service]
                                            ↓
                              [Otros Microservicios]
                              (Validan tokens con Auth)
```

### Ejemplo de Gateway (nginx):

```nginx
server {
    listen 80;
    server_name api.example.com;

    location /api/auth {
        proxy_pass http://auth-service:3001;
    }

    location /api/barbershop {
        proxy_pass http://barbershop-service:3002;
    }
}
```

## 🐛 Troubleshooting

**Error: `connection refused` en PostgreSQL**
- Verifica que PostgreSQL está corriendo
- Comprueba credenciales en .env
- Con Docker: `docker-compose ps`

**Error: `JWT malformed`**
- Verifica que estás enviando el token correctamente en el header
- Formato correcto: `Authorization: Bearer TOKEN`

**Error: `port 3001 already in use`**
- Cambia el PORT en .env
- O mata el proceso: `lsof -i :3001`

**Base de datos vacía al iniciar Docker Compose**
- Asegúrate que `schema.sql` está en la ruta correcta
- Reinicia los contenedores: `docker-compose down && docker-compose up`

## 📚 Recursos

- [JWT.io](https://jwt.io) - Info sobre JWT
- [Express.js](https://expressjs.com) - Documentación
- [PostgreSQL Docs](https://www.postgresql.org/docs/)
- [Bcrypt](https://github.com/kelektiv/node.bcrypt.js)
- [Docker Docs](https://docs.docker.com/)

## 📝 Licencia

Este proyecto es código del equipo de desarrollo interno.

## ✨ Próximas mejoras

- [ ] Implementar rate limiting
- [ ] Agregar autenticación con OAuth 2.0
- [ ] 2FA (Two-Factor Authentication)
- [ ] Recuperación de contraseña
- [ ] Auditoría y logging avanzado
- [ ] Métricas y monitoreo
- [ ] Cache de tokens con Redis

## 👥 Soporte

Para preguntas o problemas, contacta al equipo de desarrollo.

---

**Última actualización:** Octubre 2025  
**Versión:** 1.0.0