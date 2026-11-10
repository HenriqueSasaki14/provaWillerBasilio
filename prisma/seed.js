import bcrypt from "bcryptjs";
import { prisma } from "../src/lib/prisma.ts";

const senha = await bcrypt.hash("123456", 10);

await prisma.usuario.upsert({
  where: { email: "tecnico@helpdesk.com" },
  update: {},
  create: { nome: "Técnico", email: "tecnico@helpdesk.com", senha, perfil: "TECNICO" },
});

console.log("Usuário criado: tecnico@helpdesk.com / 123456");
await prisma.$disconnect();