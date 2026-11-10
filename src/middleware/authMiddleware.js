import jwt from "jsonwebtoken";

export function verificarToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ erro: "Faça login." });

  try {
    req.usuario = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ erro: "Sessão expirada. Faça login novamente." });
  }
}
