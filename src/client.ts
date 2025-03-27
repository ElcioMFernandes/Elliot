import { PrismaClient } from "@prisma/client";

// Cria uma instância global do Prisma Client
const prisma = new PrismaClient();

export default prisma;
