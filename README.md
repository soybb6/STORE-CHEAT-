
# BB6 Shop (web)

- Login con Google y Discord (si no configuras claves, aparece **Login de prueba**).
- Categorías: Roblox, MTA, Spoofers.
- Productos con imagen y link de descarga.
- Descarga protegida por **clave** de un solo uso (30 generadas al iniciar).
- Soporte (tickets).
- Admin (`/admin`): productos, usuarios, claves, tickets.
- Primer usuario que inicia sesión se vuelve **admin**.

## Arranque
```bash
npm i
cp .env.example .env   # Rellena BASE_URL y SESSION_SECRET; opcional OAuth
npm start
```
Abre `http://localhost:3000`

## Producción
Usa cualquier host Node (Render, Railway, VPS). Establece las variables del `.env`.
