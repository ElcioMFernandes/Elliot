import express, { Request, Response } from "express";
import prisma from "./client";

// Extensão da interface Request para incluir a propriedade requestTime
declare global {
  namespace Express {
    interface Request {
      requestTime?: number;
    }
  }
}

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware para processar JSON
app.use(express.json());

app.use(async (req: Request, res: Response, next) => {
  if (req.path != "/api/logs") {
    await prisma.requestLog.create({
      data: {
        method: req.method,
        path: req.path,
        url: req.url,
        headers: JSON.stringify(req.headers),
        query: JSON.stringify(req.query),
        body: JSON.stringify(req.body),
        host: req.hostname,
      },
    });
  }

  console.log(
    `${req.method} ${req.url} - ${new Date().toLocaleString()} - ${
      req.hostname
    }`
  );
  next();
});

// Rota raiz
app.get("/", (req: Request, res: Response) => {
  res.send("Bem-vindo à API Elliot!");
});

// Exemplo de rota adicional
app.get("/api/status", (req: Request, res: Response) => {
  res.json({
    status: "online",
    timestamp: new Date(),
    versão: "1.0.0",
  });
});

// Rota para consulta de logs
app.get("/api/logs", async (req: Request, res: Response) => {
  const logs = await prisma.requestLog.findMany();

  res.json(logs);
});

app.get("/api/user/:id", async (req: Request, res: Response) => {
  const { id } = req.params;

  const user = await prisma.user.findUnique({
    where: {
      id: parseInt(id),
    },
  });

  res.json(user);
});

app.post("/api/user", async (req: Request, res: Response) => {
  const { email, username, password, name } = req.body;
  try {
    const user = await prisma.user.create({
      data: {
        email,
        username,
        password,
        name,
      },
    });

    res.json(user);
  } catch (error) {
    res
      .status(400)
      .json({
        error:
          error instanceof Error ? error.message : "An unknown error occurred",
      });
  }
});

// Iniciar o servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
