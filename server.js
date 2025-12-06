require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const port = process.env.PORT || 3000;

// CORS liberado para qualquer origem (pode ajustar depois)
app.use(cors({ origin: "*" }));
app.use(express.json());

// Conexão com PostgreSQL no Railway
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Middleware para verificar token JWT
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).json({ error: "Token não informado" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET || "segredo-super", (err, user) => {
    if (err) return res.status(403).json({ error: "Token inválido" });
    req.user = user; // { id, username, role }
    next();
  });
}

// Middleware para roles
function requireRole(roles = []) {
  return (req, res, next) => {
    if (!req.user)
      return res.status(401).json({ error: "Não autenticado" });

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Permissão negada" });
    }

    next();
  };
}

// Garante ADMIN padrão caso a tabela esteja vazia
async function ensureAdminUser() {
  try {
    const result = await pool.query("SELECT COUNT(*) FROM users");
    const count = Number(result.rows[0].count || 0);

    if (count === 0) {
      const username = "admin";
      const password = "1234";
      const role = "admin";
      const hash = await bcrypt.hash(password, 10);

      await pool.query(
        "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)",
        [username, hash, role]
      );

      console.log("Usuário admin padrão criado: admin / 1234");
    }
  } catch (err) {
    console.error("Erro ao garantir admin padrão:", err);
  }
}

// ------------ LOGIN ------------
app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;

  console.log("Tentativa de login:", username);

  try {
    const result = await pool.query(
      "SELECT id, username, password_hash, role FROM users WHERE username = $1",
      [username]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({ error: "Usuário ou senha inválidos" });
    }

    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);

    if (!ok) return res.status(401).json({ error: "Usuário ou senha inválidos" });

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET || "segredo-super",
      { expiresIn: "8h" }
    );

    res.json({
      token,
      user: { id: user.id, username: user.username, role: user.role },
    });
  } catch (err) {
    console.error("Erro login:", err);
    res.status(500).json({ error: "Erro interno no servidor" });
  }
});

// ------------ CRUD DE USUÁRIOS ------------

// Criar usuário (ADMIN)
app.post("/users", authMiddleware, requireRole(["admin"]), async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password || !role)
    return res.status(400).json({ error: "Dados incompletos" });

  try {
    const hash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id, username, role",
      [username, hash, role]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error("Erro criar usuário:", err);

    if (err.code === "23505") {
      return res.status(400).json({ error: "Usuário já existe" });
    }

    res.status(500).json({ error: "Erro interno" });
  }
});

// Listar usuários
app.get("/users", authMiddleware, requireRole(["admin"]), async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, username, role FROM users ORDER BY username"
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Erro listar usuários:", err);
    res.status(500).json({ error: "Erro interno" });
  }
});

// Deletar usuário
app.delete("/users/:id", authMiddleware, requireRole(["admin"]), async (req, res) => {
  const { id } = req.params;

  if (Number(id) === req.user.id)
    return res.status(400).json({ error: "Você não pode excluir a si mesmo" });

  try {
    await pool.query("DELETE FROM users WHERE id = $1", [id]);
    res.status(204).end();
  } catch (err) {
    console.error("Erro deletar usuário:", err);
    res.status(500).json({ error: "Erro interno" });
  }
});

// ------------ CRUD PRODUTOS ------------

app.get("/products", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM products ORDER BY name");
    res.json(result.rows);
  } catch (err) {
    console.error("Erro listar produtos:", err);
    res.status(500).json({ error: "Erro interno" });
  }
});

app.post("/products", authMiddleware, requireRole(["admin", "gestor"]), async (req, res) => {
  const {
    name,
    code,
    unit,
    cost_raw,
    cost_packaging,
    cost_labor,
    cost_logistics_base,
    cost_tax_base,
    cost_other,
  } = req.body;

  if (!name)
    return res.status(400).json({ error: "Nome é obrigatório" });

  try {
    const result = await pool.query(
      `INSERT INTO products
      (name, code, unit, cost_raw, cost_packaging, cost_labor,
      cost_logistics_base, cost_tax_base, cost_other)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
      RETURNING *`,
      [
        name,
        code,
        unit,
        cost_raw || 0,
        cost_packaging || 0,
        cost_labor || 0,
        cost_logistics_base || 0,
        cost_tax_base || 0,
        cost_other || 0,
      ]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error("Erro criar produto:", err);
    res.status(500).json({ error: "Erro interno" });
  }
});

// ------------ CRUD LOCAIS ------------

app.get("/locations", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM locations ORDER BY name");
    res.json(result.rows);
  } catch (err) {
    console.error("Erro listar locais:", err);
    res.status(500).json({ error: "Erro interno" });
  }
});

app.post("/locations", authMiddleware, requireRole(["admin", "gestor"]), async (req, res) => {
  const { name, state, city, freight, extra_tax_percent, other_adjust_percent } = req.body;

  if (!name)
    return res.status(400).json({ error: "Nome é obrigatório" });

  try {
    const result = await pool.query(
      `INSERT INTO locations
      (name, state, city, freight, extra_tax_percent, other_adjust_percent)
      VALUES ($1,$2,$3,$4,$5,$6)
      RETURNING *`,
      [
        name,
        state,
        city,
        freight || 0,
        extra_tax_percent || 0,
        other_adjust_percent || 0,
      ]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error("Erro criar local:", err);
    res.status(500).json({ error: "Erro interno" });
  }
});

// ------------ START SERVER ------------

(async () => {
  try {
    await pool.query("SELECT 1");
    console.log("Conectado ao banco com sucesso.");
    await ensureAdminUser();
  } catch (err) {
    console.error("Erro ao conectar no banco:", err);
  }

  // ESSENCIAL PARA O RAILWAY
  app.listen(port, "0.0.0.0", () => {
    console.log(`API rodando na porta ${port}`);
  });
})();
