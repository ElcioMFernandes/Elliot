import bcrypt from "bcrypt";
import prisma from "./client";
import jwt from "jsonwebtoken";
import swaggerJsDoc from "swagger-jsdoc";
import swaggerUi from "swagger-ui-express";
import express, { Request, Response } from "express";

const app = express();
const PORT = process.env.PORT || 3000;
const ACCESS_TOKEN_SECRET =
  process.env.ACCESS_TOKEN_SECRET || "access_secret_key";
const REFRESH_TOKEN_SECRET =
  process.env.REFRESH_TOKEN_SECRET || "refresh_secret_key";
const ACCESS_TOKEN_EXPIRY = "15m"; // 15 minutos
const REFRESH_TOKEN_EXPIRY = "1d"; // 1 dia

// Configuração do Swagger
const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "API Elliot",
      version: "1.0.0",
      description: "Documentação da API Elliot",
    },
    servers: [
      {
        url: `http://localhost:${PORT}`,
        description: "Servidor de desenvolvimento",
      },
    ],
  },
  apis: ["./src/*.ts"], // Arquivos onde estão seus endpoints
};

// Configuração do Swagger
const swaggerDocs = swaggerJsDoc(swaggerOptions);

// Middleware para servir a documentação Swagger
app.use("/api/docs", swaggerUi.serve, swaggerUi.setup(swaggerDocs));

// Middleware para processar JSON
app.use(express.json());

// Middleware para log de requisições
app.use(async (req: Request, res: Response, next) => {
  // Não registrar logs de requisições para a rota /api/logs
  if (req.path != "/api/logs") {
    // Criar uma cópia do corpo da requisição para sanitizar, evitando log de dados sensíveis
    const sanitized = { ...req.body };

    // Verificar e sanitizar dados sensíveis
    if (sanitized.password) {
      sanitized.password = "[REDACTED]";
    }

    // Salvar log da requisição no banco de dados
    await prisma.requestLog.create({
      data: {
        method: req.method, // Método HTTP utilizado na requisição
        path: req.path, // Caminho da URL utilizado na requisição
        url: req.url, // URL completa utilizada na requisição
        headers: JSON.stringify(req.headers), // Cabeçalhos da requisição
        query: JSON.stringify(req.query), // Parâmetros da URL
        body: JSON.stringify(sanitized), // Corpo da requisição
        host: req.hostname, // Host da requisição
      },
    });
  }
  // Continuar com o fluxo normal da aplicação
  next();
});

// Endpoint para verificar se a API está online
app.get("/", (req: Request, res: Response) => {
  /**
   * @swagger
   * /:
   *  get:
   *   summary: Verifica se a API está online
   *   tags: [Status]
   *   requestBody:
   *    required: false
   *  responses:
   *   200:
   *    message: API online
   *  404:
   *   message: API offline
   */

  // Retornar mensagem de API online
  res.json({ message: "API online" });
});

// Endpoint para verificar o status da API
app.get("/api/status", (req: Request, res: Response) => {
  /**
   * @swagger
   * /api/status:
   *  get:
   *   summary: Verifica o status da API
   *   tags: [Status]
   *   requestBody:
   *    required: false
   *   responses:
   *    200:
   *      description: API online
   *      content:
   *       application/json:
   *        schema:
   *         type: object
   *         properties:
   *          status:
   *           type: string
   *          timestamp:
   *           type: string
   *          versão:
   *           type: string
   */

  // Retornar status da API
  res.json({
    status: "online",
    timestamp: new Date(),
    versão: "1.0.0",
  });
});

// Rota para consulta de logs
app.get("/api/logs", async (req: Request, res: Response) => {
  /**
   * @swagger
   * /api/logs:
   *   get:
   *     summary: Recupera todos os logs de requisições
   *     tags: [Logs]
   *     responses:
   *       200:
   *         description: Lista de logs recuperada com sucesso
   *         content:
   *           application/json:
   *             schema:
   *               type: array
   *               items:
   *                 type: object
   *                 properties:
   *                   id:
   *                     type: string
   *                   method:
   *                     type: string
   *                     description: Método HTTP da requisição
   *                   path:
   *                     type: string
   *                     description: Caminho da requisição
   *                   statusCode:
   *                     type: integer
   *                     description: Código de status da resposta
   *                   timestamp:
   *                     type: string
   *                     format: date-time
   *                     description: Data e hora do registro do log
   *       500:
   *         description: Erro ao recuperar logs
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   */

  // Consultar logs no banco de dados
  const logs = await prisma.requestLog.findMany();
  // Retornar logs encontrados
  res.json(logs);
});

// Endpoint para consulta de usuários
app.get("/api/user/:id", async (req: Request, res: Response) => {
  /**
   * @swagger
   * /api/user/{id}:
   *   get:
   *     summary: Recupera um usuário pelo ID
   *     tags: [Usuários]
   *     parameters:
   *       - in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: integer
   *         description: ID do usuário
   *     responses:
   *       200:
   *         description: Dados do usuário recuperados com sucesso
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 id:
   *                   type: integer
   *                 email:
   *                   type: string
   *                 username:
   *                   type: string
   *                 name:
   *                   type: string
   *                 createdAt:
   *                   type: string
   *                   format: date-time
   *       404:
   *         description: Usuário não encontrado
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   example: "User not found"
   */

  // Extrair o ID do parâmetro da URL
  const { id } = req.params;

  // Encontrar o usuário no banco de
  const user = await prisma.user.findUnique({
    where: {
      id: parseInt(id),
    },
  });

  // Retornar o usuário encontrado
  res.json(user);
});

// Endpoint para criação de usuários
app.post("/api/user", async (req: Request, res: Response) => {
  /**
   * @swagger
   * /api/user:
   *   post:
   *     summary: Cria um novo usuário
   *     tags: [Usuários]
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               email:
   *                 type: string
   *                 format: email
   *                 description: Email do usuário
   *               username:
   *                 type: string
   *                 description: Nome de usuário único
   *               password:
   *                 type: string
   *                 format: password
   *                 description: Senha do usuário
   *               name:
   *                 type: string
   *                 description: Nome completo do usuário
   *             required:
   *               - email
   *               - username
   *               - password
   *               - name
   *     responses:
   *       200:
   *         description: Usuário criado com sucesso
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 id:
   *                   type: string
   *                 email:
   *                   type: string
   *                 username:
   *                   type: string
   *                 name:
   *                   type: string
   *                 createdAt:
   *                   type: string
   *                   format: date-time
   *       409:
   *         description: Nome de usuário ou email já em uso
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *       400:
   *         description: Erro ao criar o usuário
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   */

  // Extrair email, username, password e name do corpo da requisição
  const { email, username, password, name } = req.body;

  // Verificar se o email ou username já estão em uso
  try {
    const exists = await prisma.user.findFirst({
      where: {
        OR: [
          {
            email,
          },
          {
            username,
          },
        ],
      },
    });

    // Retornar erro 409 se o email ou username já estiverem em uso
    if (exists) {
      res.status(409).json({ error: "Username or email already in use" });
      return;
    }

    // Gerar salt e criptografar a senha
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Salvar usuário no banco de dados
    const user = await prisma.user.create({
      data: {
        email,
        username,
        password: hashedPassword,
        name,
      },
    });

    // Não retornar a senha no response
    const { password: _, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
  } catch (error) {
    // Retornar erro 400 se houver algum erro
    res.status(400).json({
      error:
        error instanceof Error ? error.message : "An unknown error occurred",
    });
  }
});

// Endpoint para autenticação de usuários
app.post("/api/auth", async (req: Request, res: Response) => {
  /**
   * @swagger
   * /api/auth:
   *   post:
   *     summary: Realiza a autenticação de um usuário
   *     tags: [Autenticação]
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               email:
   *                 type: string
   *               username:
   *                 type: string
   *               password:
   *                 type: string
   *             required:
   *               - password
   *     responses:
   *       200:
   *         description: Autenticação bem-sucedida
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 accessToken:
   *                   type: string
   *                 refreshToken:
   *                   type: string
   *       401:
   *         description: Credenciais inválidas
   */

  // Extrair email, username e password do corpo da requisição
  const { username, email, password } = req.body;

  // Encontrar o usuário no banco de dados
  const user = await prisma.user.findFirst({
    where: {
      OR: [
        {
          email,
        },
        {
          username,
        },
      ],
    },
  });

  // Se o usuário não existir, retornar erro 401
  if (!user) {
    res.status(401).json({ error: "Invalid credentials" });
    return;
  }

  // Comparar a senha informada com a senha criptografada
  const passwordMatch = await bcrypt.compare(password, user.password);

  // Se as senhas não coincidirem, retornar erro 401
  if (!passwordMatch) {
    res.status(401).json({ error: "Invalid credentials" });
    return;
  }

  // Payload do token (Dados que serão incluídos no token)
  const payload = {
    id: user.id,
    username: user.username,
    email: user.email,
  };

  // Gerar token de acesso e token de refresh
  const accessToken = jwt.sign(payload, ACCESS_TOKEN_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRY,
  });

  const refreshToken = jwt.sign(payload, REFRESH_TOKEN_SECRET, {
    expiresIn: REFRESH_TOKEN_EXPIRY,
  });

  // Calcular data de expiração do token de refresh
  const expiredAt = new Date();
  expiredAt.setDate(expiredAt.getDate() + 1);

  // Salvar token de refresh no banco de dados
  await prisma.token.create({
    data: {
      access: accessToken,
      refresh: refreshToken,
      expiredAt,
      userId: user.id,
    },
  });

  // Retornar os tokens gerados
  res.json({ accessToken, refreshToken });
});

// Endpoint que verifica se o token é válido
app.post("/api/verify", async (req: Request, res: Response) => {
  /**
   * @swagger
   * /api/verify:
   *   post:
   *     summary: Verifica a validade de um token de acesso
   *     tags: [Autenticação]
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               accessToken:
   *                 type: string
   *                 description: Token de acesso JWT a ser verificado
   *             required:
   *               - accessToken
   *     responses:
   *       200:
   *         description: Token válido
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 valid:
   *                   type: boolean
   *                   example: true
   *                 user:
   *                   type: object
   *                   properties:
   *                     userId:
   *                       type: integer
   *                       example: 1
   *                     iat:
   *                       type: integer
   *                       description: Timestamp de emissão do token
   *                       example: 1716839254
   *                     exp:
   *                       type: integer
   *                       description: Timestamp de expiração do token
   *                       example: 1716840154
   *       401:
   *         description: Token inválido ou expirado
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 valid:
   *                   type: boolean
   *                   example: false
   */

  // Extrair o token de acesso do corpo da requisição
  const { accessToken } = req.body;

  // Verificar assinatura e expiração do token
  const decoded = jwt.verify(accessToken, ACCESS_TOKEN_SECRET);

  // Verificar se o token está na lista de token existe e não foi revogado
  const token = await prisma.token.findFirst({
    where: {
      access: accessToken,
      revoked: false,
      expiredAt: {
        gt: new Date(),
      },
    },
  });

  // Se o token não existir, retornar erro 401, token inválido
  if (!token) {
    res.status(401).json({ valid: false });
    return;
  }

  // Retornar o payload do token decodificado e válido
  res.status(200).json({ valid: true, user: decoded });
});

// Endpoint que renova o token de acesso

// Endpoint para revogar o token de acesso

// Iniciar o servidor
app.listen(PORT, () => {
  // Mensagem de log ao iniciar o servidor
  console.log(`                                             
     ##### ##   ###   ###                               
  ######  /### / ###   ###    #                         
 /#   /  / ###/   ##    ##   ###                  #     
/    /  /   ##    ##    ##    #                  ##     
    /  /          ##    ##                       ##     
   ## ##          ##    ##  ###       /###     ######## 
   ## ##          ##    ##   ###     / ###  / ########  
   ## ######      ##    ##    ##    /   ###/     ##     
   ## #####       ##    ##    ##   ##    ##      ##     
   ## ##          ##    ##    ##   ##    ##      ##     
   #  ##          ##    ##    ##   ##    ##      ##     
      /           ##    ##    ##   ##    ##      ##     
  /##/         /  ##    ##    ##   ##    ##      ##     
 /  ##########/   ### / ### / ### / ######       ##     
/     ######       ##/   ##/   ##/   ####         ##    
#                                                       
 ##
 
API Elliot iniciada na porta ${PORT}.

Acesse ao endpoint /api/docs para ver a documentação da API.
`);
});
