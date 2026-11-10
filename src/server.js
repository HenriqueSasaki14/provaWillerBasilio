import "dotenv/config";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { prisma } from "./lib/prisma.ts";
import { verificarToken } from "./middleware/authMiddleware.js";

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
  origin: ["http://localhost:5500", "http://127.0.0.1:5500"],
  credentials: true,
}));
app.use(express.json());
app.use(cookieParser());


app.post("/auth/registro", async (req, res) => {
  const { nome, email, senha } = req.body;
  if (!nome || !email || !senha) {
    return res.status(400).json({ erro: "Nome, e-mail e senha são obrigatórios." });
  }

  try {
    const senhaHash = await bcrypt.hash(senha, 10);
    const usuario = await prisma.usuario.create({ data: { nome, email, senha: senhaHash } });
    res.status(201).json({ id: usuario.id, nome: usuario.nome, email: usuario.email });
  } catch (error) {
    res.status(400).json({ erro: "E-mail já cadastrado." });
  }
});

app.post("/auth/login", async (req, res) => {
  const { email, senha } = req.body;

  const usuario = await prisma.usuario.findUnique({ where: { email } });
  if (!usuario || !(await bcrypt.compare(senha, usuario.senha))) {
    return res.status(401).json({ erro: "E-mail ou senha inválidos." });
  }

  const dados = { id: usuario.id, nome: usuario.nome, perfil: usuario.perfil };
  const token = jwt.sign(dados, process.env.JWT_SECRET, { expiresIn: "1h" });

  res.cookie("token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: false,
    maxAge: 60 * 60 * 1000,
  });
  res.json(dados);
});

app.get("/auth/me", verificarToken, (req, res) => {
  res.json(req.usuario);
});

app.post("/auth/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ mensagem: "Logout realizado." });
});


app.get("/chamados", verificarToken, async (req, res) => {
  const filtro = req.usuario.perfil === "TECNICO" ? {} : { usuarioId: req.usuario.id };

  const chamados = await prisma.chamado.findMany({
    where: filtro,
    include: { usuario: { select: { nome: true, email: true } } },
    orderBy: { prazo: "asc" },
  });
  res.json(chamados);
});

app.post("/chamados", verificarToken, async (req, res) => {
  const { titulo, descricao, prioridade } = req.body;
  if (!titulo || !descricao || !PRAZO_HORAS[prioridade]) {
    return res.status(400).json({ erro: "Título, descrição e prioridade (BAIXA, MEDIA, ALTA) são obrigatórios." });
  }

  const prazo = new Date(Date.now() + PRAZO_HORAS[prioridade] * 60 * 60 * 1000);

  const chamado = await prisma.chamado.create({
    data: { titulo, descricao, prioridade, prazo, usuarioId: req.usuario.id },
  });
  res.status(201).json(chamado);
});

app.put("/chamados/:id", verificarToken, async (req, res) => {
  const id = Number(req.params.id);
  const { titulo, descricao, prioridade, status } = req.body;

  const chamado = await prisma.chamado.findUnique({ where: { id } });
  if (!chamado) return res.status(404).json({ erro: "Chamado não encontrado." });

  const ehTecnico = req.usuario.perfil === "TECNICO";
  if (!ehTecnico && chamado.usuarioId !== req.usuario.id) {
    return res.status(403).json({ erro: "Sem permissão para este chamado." });
  }
  if (status && !ehTecnico) {
    return res.status(403).json({ erro: "Só o técnico pode alterar o status." });
  }
  if (status && !STATUS.includes(status)) {
    return res.status(400).json({ erro: "Status inválido." });
  }
  if (prioridade && !PRAZO_HORAS[prioridade]) {
    return res.status(400).json({ erro: "Prioridade inválida." });
  }

  const atualizado = await prisma.chamado.update({
    where: { id },
    data: { titulo, descricao, prioridade, status },
  });
  res.json(atualizado);
});

app.delete("/chamados/:id", verificarToken, async (req, res) => {
  const id = Number(req.params.id);

  const chamado = await prisma.chamado.findUnique({ where: { id } });
  if (!chamado) return res.status(404).json({ erro: "Chamado não encontrado." });

  if (req.usuario.perfil !== "TECNICO" && chamado.usuarioId !== req.usuario.id) {
    return res.status(403).json({ erro: "Sem permissão para este chamado." });
  }

  await prisma.chamado.delete({ where: { id } });
  res.status(204).send();
});


app.listen(PORT, () => {
    console.log("Server na porta 3000")
})