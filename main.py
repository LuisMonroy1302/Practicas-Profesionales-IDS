"""
GEOCUSTOMERS - API REST (FastAPI)
Puente entre la app Android y PostgreSQL (local o Neon en la nube).
Ejecución local: uvicorn main:app --host 0.0.0.0 --port 8000
Requiere la variable de entorno DATABASE_URL (definida en iniciar_api.bat o en Render).
"""
import os
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Optional

import psycopg2
import jwt
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="GEOCUSTOMERS API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# La conexión se toma de la variable de entorno (nunca contraseñas en el código)
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("Falta la variable de entorno DATABASE_URL")

SECRET_KEY = "geocustomers-piloto-2026"
ALGORITHM = "HS256"


def get_conn():
    # Neon exige SSL; la base local funciona sin parámetros adicionales
    if "neon.tech" in DATABASE_URL:
        return psycopg2.connect(DATABASE_URL, sslmode="require")
    return psycopg2.connect(DATABASE_URL)


def hash_sha256(texto: str) -> str:
    return sha256(texto.encode()).hexdigest()


# ---------------- Seguridad: verificación de rol ----------------
def obtener_payload(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Token no proporcionado")
    token = authorization.split(" ", 1)[1]
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Sesión expirada, inicie sesión nuevamente")
    except jwt.PyJWTError:
        raise HTTPException(401, "Token inválido")


def requerir_admin(payload: dict = Depends(obtener_payload)):
    if payload.get("rol") != "Administrador":
        raise HTTPException(403, "Privilegios de Administrador requeridos")
    return payload


# ---------------- Modelos de datos (Pydantic) ----------------
class LoginIn(BaseModel):
    numero_empleado: str
    password: str


class GrupoIn(BaseModel):
    nombre_grupo: str
    centro_trabajo: str = "536401"


class GrupoUpdate(BaseModel):
    nombre_grupo: str
    centro_trabajo: str = "536401"


class SupervisorIn(BaseModel):
    nombre_completo: str
    numero_empleado: int
    grupo_id: int


class SupervisorUpdate(BaseModel):
    nombre_completo: str
    numero_empleado: int


class ZonaIn(BaseModel):
    nombre_zona: str
    supervisor_id: int


class ZonaUpdate(BaseModel):
    nombre_zona: str


class ClienteIn(BaseModel):
    numero_cliente: str
    nombre_completo: str
    referencia_domicilio: Optional[str] = None
    latitud: float
    longitud: float
    zona_id: int


class UsuarioIn(BaseModel):
    numero_empleado: str
    password: str
    nombre: str
    rol: str = "Supervisor"
    grupo_id: Optional[int] = None


class UsuarioUpdate(BaseModel):
    nombre: Optional[str] = None
    password: Optional[str] = None
    rol: Optional[str] = None


# ---------------- Salud del servicio ----------------
@app.get("/")
def root():
    return {"mensaje": "GEOCUSTOMERS API activa", "version": "1.0.0"}


# ---------------- Autenticación ----------------
@app.post("/login")
def login(datos: LoginIn):
    conn = get_conn(); cur = conn.cursor()
    cur.execute(
        "SELECT nombre, rol FROM usuarios "
        "WHERE numero_empleado = %s AND password_hash = %s",
        (datos.numero_empleado, hash_sha256(datos.password)),
    )
    fila = cur.fetchone()
    if not fila:
        cur.close(); conn.close()
        raise HTTPException(401, "Número de empleado o contraseña incorrectos")
    nombre, rol = fila

    # Vínculo con el registro de supervisor (si el número de empleado coincide)
    supervisor_id = None
    grupo_id = None
    if datos.numero_empleado.isdigit():
        cur.execute(
            "SELECT supervisor_id, grupo_id FROM supervisores WHERE numero_empleado = %s",
            (int(datos.numero_empleado),),
        )
        sup = cur.fetchone()
        if sup:
            supervisor_id, grupo_id = sup
    cur.close(); conn.close()

    token = jwt.encode(
        {"sub": datos.numero_empleado, "nombre": nombre, "rol": rol,
         "supervisor_id": supervisor_id,
         "exp": datetime.now(timezone.utc) + timedelta(hours=8)},
        SECRET_KEY, algorithm=ALGORITHM,
    )
    return {"token": token, "nombre": nombre, "rol": rol,
            "supervisor_id": supervisor_id, "grupo_id": grupo_id}


# ---------------- Grupos (lectura libre, escritura solo Administrador) ----------------
@app.get("/grupos")
def listar_grupos():
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT grupo_id, nombre_grupo, centro_trabajo FROM grupos ORDER BY grupo_id")
    filas = cur.fetchall(); cur.close(); conn.close()
    return [{"grupo_id": f[0], "nombre_grupo": f[1], "centro_trabajo": f[2]} for f in filas]


@app.post("/grupos", status_code=201)
def crear_grupo(g: GrupoIn, _: dict = Depends(requerir_admin)):
    conn = get_conn(); cur = conn.cursor()
    cur.execute(
        "INSERT INTO grupos (nombre_grupo, centro_trabajo) VALUES (%s, %s) RETURNING grupo_id",
        (g.nombre_grupo, g.centro_trabajo),
    )
    nuevo_id = cur.fetchone()[0]
    conn.commit(); cur.close(); conn.close()
    return {"grupo_id": nuevo_id, "nombre_grupo": g.nombre_grupo}


@app.put("/grupos/{grupo_id}")
def actualizar_grupo(grupo_id: int, g: GrupoUpdate, _: dict = Depends(requerir_admin)):
    conn = get_conn(); cur = conn.cursor()
    cur.execute(
        "UPDATE grupos SET nombre_grupo = %s, centro_trabajo = %s "
        "WHERE grupo_id = %s RETURNING grupo_id",
        (g.nombre_grupo, g.centro_trabajo, grupo_id),
    )
    fila = cur.fetchone()
    if not fila:
        cur.close(); conn.close()
        raise HTTPException(404, "Grupo no encontrado")
    conn.commit(); cur.close(); conn.close()
    return {"grupo_id": grupo_id, "nombre_grupo": g.nombre_grupo,
            "centro_trabajo": g.centro_trabajo}


@app.delete("/grupos/{grupo_id}")
def eliminar_grupo(grupo_id: int, _: dict = Depends(requerir_admin)):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM supervisores WHERE grupo_id = %s", (grupo_id,))
    if cur.fetchone()[0] > 0:
        cur.close(); conn.close()
        raise HTTPException(409, "No se puede eliminar el grupo: tiene supervisores asociados")
    cur.execute("DELETE FROM grupos WHERE grupo_id = %s RETURNING grupo_id", (grupo_id,))
    fila = cur.fetchone()
    if not fila:
        cur.close(); conn.close()
        raise HTTPException(404, "Grupo no encontrado")
    conn.commit(); cur.close(); conn.close()
    return {"mensaje": "Grupo eliminado correctamente"}


# ---------------- Supervisores (lectura libre, escritura solo Administrador) ----------------
@app.get("/supervisores")
def listar_supervisores(grupo_id: int = None):
    conn = get_conn(); cur = conn.cursor()
    if grupo_id is not None:
        cur.execute(
            "SELECT supervisor_id, nombre_completo, numero_empleado, grupo_id "
            "FROM supervisores WHERE grupo_id = %s ORDER BY supervisor_id",
            (grupo_id,),
        )
    else:
        cur.execute(
            "SELECT supervisor_id, nombre_completo, numero_empleado, grupo_id "
            "FROM supervisores ORDER BY supervisor_id"
        )
    filas = cur.fetchall(); cur.close(); conn.close()
    return [{"supervisor_id": f[0], "nombre_completo": f[1],
             "numero_empleado": f[2], "grupo_id": f[3]} for f in filas]


@app.post("/supervisores", status_code=201)
def crear_supervisor(s: SupervisorIn, _: dict = Depends(requerir_admin)):
    conn = get_conn(); cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO supervisores (nombre_completo, numero_empleado, grupo_id) "
            "VALUES (%s, %s, %s) RETURNING supervisor_id",
            (s.nombre_completo, s.numero_empleado, s.grupo_id),
        )
        nuevo_id = cur.fetchone()[0]
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback(); cur.close(); conn.close()
        raise HTTPException(409, "El número de empleado ya está registrado")
    cur.close(); conn.close()
    return {"supervisor_id": nuevo_id, "nombre_completo": s.nombre_completo,
            "numero_empleado": s.numero_empleado, "grupo_id": s.grupo_id}


@app.put("/supervisores/{supervisor_id}")
def actualizar_supervisor(supervisor_id: int, s: SupervisorUpdate,
                          _: dict = Depends(requerir_admin)):
    conn = get_conn(); cur = conn.cursor()
    try:
        cur.execute(
            "UPDATE supervisores SET nombre_completo = %s, numero_empleado = %s "
            "WHERE supervisor_id = %s RETURNING supervisor_id",
            (s.nombre_completo, s.numero_empleado, supervisor_id),
        )
        fila = cur.fetchone()
        if not fila:
            cur.close(); conn.close()
            raise HTTPException(404, "Supervisor no encontrado")
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback(); cur.close(); conn.close()
        raise HTTPException(409, "El número de empleado ya está registrado")
    cur.close(); conn.close()
    return {"supervisor_id": supervisor_id, "nombre_completo": s.nombre_completo,
            "numero_empleado": s.numero_empleado}


@app.delete("/supervisores/{supervisor_id}")
def eliminar_supervisor(supervisor_id: int, _: dict = Depends(requerir_admin)):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM zonas WHERE supervisor_id = %s", (supervisor_id,))
    if cur.fetchone()[0] > 0:
        cur.close(); conn.close()
        raise HTTPException(409, "No se puede eliminar el supervisor: tiene zonas asociadas")
    cur.execute("DELETE FROM supervisores WHERE supervisor_id = %s RETURNING supervisor_id", (supervisor_id,))
    fila = cur.fetchone()
    if not fila:
        cur.close(); conn.close()
        raise HTTPException(404, "Supervisor no encontrado")
    conn.commit(); cur.close(); conn.close()
    return {"mensaje": "Supervisor eliminado correctamente"}


# ---------------- Zonas (lectura libre, escritura solo Administrador) ----------------
@app.get("/zonas")
def listar_zonas(supervisor_id: int = None):
    conn = get_conn(); cur = conn.cursor()
    if supervisor_id is not None:
        cur.execute(
            "SELECT zona_id, nombre_zona, supervisor_id FROM zonas "
            "WHERE supervisor_id = %s ORDER BY zona_id", (supervisor_id,),
        )
    else:
        cur.execute("SELECT zona_id, nombre_zona, supervisor_id FROM zonas ORDER BY zona_id")
    filas = cur.fetchall(); cur.close(); conn.close()
    return [{"zona_id": f[0], "nombre_zona": f[1], "supervisor_id": f[2]} for f in filas]


@app.post("/zonas", status_code=201)
def crear_zona(z: ZonaIn, _: dict = Depends(requerir_admin)):
    conn = get_conn(); cur = conn.cursor()
    cur.execute(
        "INSERT INTO zonas (nombre_zona, supervisor_id) VALUES (%s, %s) RETURNING zona_id",
        (z.nombre_zona, z.supervisor_id),
    )
    nuevo_id = cur.fetchone()[0]
    conn.commit(); cur.close(); conn.close()
    return {"zona_id": nuevo_id, "nombre_zona": z.nombre_zona,
            "supervisor_id": z.supervisor_id}


@app.put("/zonas/{zona_id}")
def actualizar_zona(zona_id: int, z: ZonaUpdate, _: dict = Depends(requerir_admin)):
    conn = get_conn(); cur = conn.cursor()
    cur.execute(
        "UPDATE zonas SET nombre_zona = %s WHERE zona_id = %s "
        "RETURNING zona_id, supervisor_id",
        (z.nombre_zona, zona_id),
    )
    fila = cur.fetchone()
    if not fila:
        cur.close(); conn.close()
        raise HTTPException(404, "Zona no encontrada")
    conn.commit(); cur.close(); conn.close()
    return {"zona_id": zona_id, "nombre_zona": z.nombre_zona, "supervisor_id": fila[1]}


@app.delete("/zonas/{zona_id}")
def eliminar_zona(zona_id: int, _: dict = Depends(requerir_admin)):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM clientes WHERE zona_id = %s", (zona_id,))
    if cur.fetchone()[0] > 0:
        cur.close(); conn.close()
        raise HTTPException(409, "No se puede eliminar la zona: tiene clientes asociados")
    cur.execute("DELETE FROM zonas WHERE zona_id = %s RETURNING zona_id", (zona_id,))
    fila = cur.fetchone()
    if not fila:
        cur.close(); conn.close()
        raise HTTPException(404, "Zona no encontrada")
    conn.commit(); cur.close(); conn.close()
    return {"mensaje": "Zona eliminada correctamente"}


# ---------------- Clientes (sin restricción de admin: operará por zona) ----------------
@app.get("/clientes")
def listar_clientes():
    conn = get_conn(); cur = conn.cursor()
    cur.execute(
        "SELECT cliente_id, numero_cliente, nombre_completo, latitud, longitud, zona_id "
        "FROM clientes ORDER BY cliente_id"
    )
    filas = cur.fetchall(); cur.close(); conn.close()
    return [{"cliente_id": f[0], "numero_cliente": f[1], "nombre_completo": f[2],
             "latitud": f[3], "longitud": f[4], "zona_id": f[5]} for f in filas]


@app.post("/clientes", status_code=201)
def crear_cliente(c: ClienteIn):
    conn = get_conn(); cur = conn.cursor()
    cur.execute(
        "INSERT INTO clientes (numero_cliente, nombre_completo, referencia_domicilio, "
        "latitud, longitud, zona_id) VALUES (%s,%s,%s,%s,%s,%s) RETURNING cliente_id",
        (c.numero_cliente, c.nombre_completo, c.referencia_domicilio,
         c.latitud, c.longitud, c.zona_id),
    )
    nuevo_id = cur.fetchone()[0]
    conn.commit(); cur.close(); conn.close()
    return {"cliente_id": nuevo_id}


# ---------------- CRUD de usuarios (solo Administrador) ----------------
@app.get("/usuarios")
def listar_usuarios(_: dict = Depends(requerir_admin)):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT numero_empleado, nombre, rol FROM usuarios ORDER BY numero_empleado")
    filas = cur.fetchall(); cur.close(); conn.close()
    return [{"numero_empleado": f[0], "nombre": f[1], "rol": f[2]} for f in filas]


@app.post("/usuarios", status_code=201)
def crear_usuario(u: UsuarioIn, _: dict = Depends(requerir_admin)):
    if u.rol not in ("Administrador", "Supervisor"):
        raise HTTPException(422, "Rol no válido")
    if u.rol == "Supervisor" and u.grupo_id is None:
        raise HTTPException(422, "Un usuario Supervisor requiere grupo_id")
    if u.rol == "Administrador":
        raise HTTPException(409, "Solo puede existir un usuario Administrador")
    conn = get_conn(); cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO usuarios (numero_empleado, password_hash, nombre, rol) "
            "VALUES (%s, %s, %s, %s)",
            (u.numero_empleado, hash_sha256(u.password), u.nombre, u.rol),
        )
        if u.rol == "Supervisor":
            cur.execute(
                "INSERT INTO supervisores (nombre_completo, numero_empleado, grupo_id) "
                "VALUES (%s, %s, %s)",
                (u.nombre, int(u.numero_empleado), u.grupo_id),
            )
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback(); cur.close(); conn.close()
        raise HTTPException(409, "El número de empleado ya está registrado")
    except ValueError:
        conn.rollback(); cur.close(); conn.close()
        raise HTTPException(422, "El número de empleado debe ser numérico")
    cur.close(); conn.close()
    return {"numero_empleado": u.numero_empleado, "nombre": u.nombre, "rol": u.rol}


@app.put("/usuarios/{numero_empleado}")
def actualizar_usuario(numero_empleado: str, u: UsuarioUpdate,
                       _: dict = Depends(requerir_admin)):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT rol FROM usuarios WHERE numero_empleado = %s", (numero_empleado,))
    fila = cur.fetchone()
    if not fila:
        cur.close(); conn.close()
        raise HTTPException(404, "Usuario no encontrado")
    rol_actual = fila[0]
    if rol_actual == "Administrador" and u.rol and u.rol != "Administrador":
        cur.close(); conn.close()
        raise HTTPException(409, "No se puede degradar al único Administrador")
    sets, vals = [], []
    if u.nombre:
        sets.append("nombre = %s"); vals.append(u.nombre)
    if u.password:
        sets.append("password_hash = %s"); vals.append(hash_sha256(u.password))
    if u.rol:
        sets.append("rol = %s"); vals.append(u.rol)
    if sets:
        vals.append(numero_empleado)
        cur.execute(f"UPDATE usuarios SET {', '.join(sets)} WHERE numero_empleado = %s", vals)
    if u.nombre and rol_actual == "Supervisor" and numero_empleado.isdigit():
        cur.execute("UPDATE supervisores SET nombre_completo = %s WHERE numero_empleado = %s",
                    (u.nombre, int(numero_empleado)))
    conn.commit(); cur.close(); conn.close()
    return {"mensaje": "Usuario actualizado correctamente"}


@app.delete("/usuarios/{numero_empleado}")
def eliminar_usuario(numero_empleado: str, _: dict = Depends(requerir_admin)):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT rol FROM usuarios WHERE numero_empleado = %s", (numero_empleado,))
    fila = cur.fetchone()
    if not fila:
        cur.close(); conn.close()
        raise HTTPException(404, "Usuario no encontrado")
    if fila[0] == "Administrador":
        cur.close(); conn.close()
        raise HTTPException(409, "No se puede eliminar al único Administrador")
    if numero_empleado.isdigit():
        cur.execute(
            "SELECT COUNT(*) FROM zonas z JOIN supervisores s "
            "ON z.supervisor_id = s.supervisor_id WHERE s.numero_empleado = %s",
            (int(numero_empleado),),
        )
        if cur.fetchone()[0] > 0:
            cur.close(); conn.close()
            raise HTTPException(409, "No se puede eliminar: el supervisor tiene zonas asociadas")
        cur.execute("DELETE FROM supervisores WHERE numero_empleado = %s",
                    (int(numero_empleado),))
    cur.execute("DELETE FROM usuarios WHERE numero_empleado = %s", (numero_empleado,))
    conn.commit(); cur.close(); conn.close()
    return {"mensaje": "Usuario eliminado correctamente"}

# ---------------- Clientes con permiso por zona ----------------
class ClienteUpdate(BaseModel):
    numero_cliente: Optional[str] = None
    nombre_completo: Optional[str] = None
    referencia_domicilio: Optional[str] = None
    latitud: Optional[float] = None
    longitud: Optional[float] = None


def requerir_login(payload: dict = Depends(obtener_payload)):
    return payload


def zona_permitida(conn, zona_id: int, payload: dict) -> bool:
    """Verdadero si el usuario del token puede operar la zona (Admin: todas)."""
    if payload.get("rol") == "Administrador":
        return True
    sup_id = payload.get("supervisor_id")
    if sup_id is None:
        return False
    cur = conn.cursor()
    cur.execute("SELECT supervisor_id FROM zonas WHERE zona_id = %s", (zona_id,))
    fila = cur.fetchone()
    cur.close()
    return fila is not None and fila[0] == sup_id


@app.get("/clientes")
def listar_clientes(zona_id: int = None, payload: dict = Depends(requerir_login)):
    conn = get_conn(); cur = conn.cursor()
    if zona_id is not None:
        if not zona_permitida(conn, zona_id, payload):
            cur.close(); conn.close()
            raise HTTPException(403, "No tiene permiso sobre esta zona")
        cur.execute(
            "SELECT cliente_id, numero_cliente, nombre_completo, referencia_domicilio, "
            "latitud, longitud, zona_id FROM clientes WHERE zona_id = %s ORDER BY cliente_id",
            (zona_id,),
        )
    elif payload.get("rol") == "Administrador":
        cur.execute(
            "SELECT cliente_id, numero_cliente, nombre_completo, referencia_domicilio, "
            "latitud, longitud, zona_id FROM clientes ORDER BY cliente_id"
        )
    else:
        cur.execute(
            "SELECT c.cliente_id, c.numero_cliente, c.nombre_completo, "
            "c.referencia_domicilio, c.latitud, c.longitud, c.zona_id "
            "FROM clientes c JOIN zonas z ON c.zona_id = z.zona_id "
            "WHERE z.supervisor_id = %s ORDER BY c.cliente_id",
            (payload.get("supervisor_id"),),
        )
    filas = cur.fetchall(); cur.close(); conn.close()
    return [{"cliente_id": f[0], "numero_cliente": f[1], "nombre_completo": f[2],
             "referencia_domicilio": f[3], "latitud": f[4], "longitud": f[5],
             "zona_id": f[6]} for f in filas]


@app.post("/clientes", status_code=201)
def crear_cliente(c: ClienteIn, payload: dict = Depends(requerir_login)):
    conn = get_conn(); cur = conn.cursor()
    if not zona_permitida(conn, c.zona_id, payload):
        cur.close(); conn.close()
        raise HTTPException(403, "No tiene permiso para registrar clientes en esta zona")
    cur.execute(
        "INSERT INTO clientes (numero_cliente, nombre_completo, referencia_domicilio, "
        "latitud, longitud, zona_id) VALUES (%s,%s,%s,%s,%s,%s) RETURNING cliente_id",
        (c.numero_cliente, c.nombre_completo, c.referencia_domicilio,
         c.latitud, c.longitud, c.zona_id),
    )
    nuevo_id = cur.fetchone()[0]
    conn.commit(); cur.close(); conn.close()
    return {"cliente_id": nuevo_id}


@app.put("/clientes/{cliente_id}")
def actualizar_cliente(cliente_id: int, c: ClienteUpdate,
                       payload: dict = Depends(requerir_login)):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT zona_id FROM clientes WHERE cliente_id = %s", (cliente_id,))
    fila = cur.fetchone()
    if not fila:
        cur.close(); conn.close()
        raise HTTPException(404, "Cliente no encontrado")
    if not zona_permitida(conn, fila[0], payload):
        cur.close(); conn.close()
        raise HTTPException(403, "No tiene permiso sobre este cliente")
    sets, vals = [], []
    for campo in ("numero_cliente", "nombre_completo", "referencia_domicilio",
                  "latitud", "longitud"):
        valor = getattr(c, campo)
        if valor is not None:
            sets.append(f"{campo} = %s"); vals.append(valor)
    if sets:
        vals.append(cliente_id)
        cur.execute(f"UPDATE clientes SET {', '.join(sets)} WHERE cliente_id = %s", vals)
    conn.commit(); cur.close(); conn.close()
    return {"mensaje": "Cliente actualizado correctamente"}


@app.delete("/clientes/{cliente_id}")
def eliminar_cliente(cliente_id: int, payload: dict = Depends(requerir_login)):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT zona_id FROM clientes WHERE cliente_id = %s", (cliente_id,))
    fila = cur.fetchone()
    if not fila:
        cur.close(); conn.close()
        raise HTTPException(404, "Cliente no encontrado")
    if not zona_permitida(conn, fila[0], payload):
        cur.close(); conn.close()
        raise HTTPException(403, "No tiene permiso sobre este cliente")
    cur.execute("DELETE FROM clientes WHERE cliente_id = %s RETURNING cliente_id", (cliente_id,))
    conn.commit(); cur.close(); conn.close()
    return {"mensaje": "Cliente eliminado correctamente"}
