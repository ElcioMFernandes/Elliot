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
app.post("/api/access", async (req: Request, res: Response) => {
  /**
   * @swagger
   * /api/access:
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
app.post("/api/refresh", async (req: Request, res: Response) => {
  /**
   * @swagger
   * /api/refresh:
   *   post:
   *     summary: Renova o token de acesso usando um token de refresh válido
   *     tags: [Autenticação]
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               refreshToken:
   *                 type: string
   *                 description: Token de refresh JWT válido
   *             required:
   *               - refreshToken
   *     responses:
   *       200:
   *         description: Token de acesso renovado com sucesso
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 accessToken:
   *                   type: string
   *                   description: Novo token de acesso JWT
   *                   example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   *       401:
   *         description: Token de refresh não fornecido, não encontrado, revogado, expirado ou usuário não encontrado
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   example: Refresh token not provided
   *       403:
   *         description: Token de refresh inválido
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   example: Invalid refresh token
   */
  // Obter o token de refresh do corpo da requisição
  const refreshToken = req.body.refreshToken;

  // Verifica se o token de refresh foi enviado
  refreshToken
    ? // Verifica se o token de refresh é válido
      jwt.verify(
        refreshToken,
        REFRESH_TOKEN_SECRET,
        async (err: any, user: any) => {
          // Se o token de refresh for inválido, retorna erro 401
          if (err) {
            return res.status(403).json({ error: "Invalid refresh token" });
          }
          // Verifica se o token de refresh está na lista de tokens e não foi revogado

          const token = await prisma.token.findFirst({
            where: {
              refresh: refreshToken,
              revoked: false,
              expiredAt: {
                gt: new Date(),
              },
            },
          });

          // Se o token de refresh não existir, retorna erro 401
          if (!token) {
            return res.status(401).json({ error: "Refresh token not found" });
          }
          // Verifica se o token de refresh foi revogado
          if (token.revoked) {
            return res.status(401).json({ error: "Refresh token revoked" });
          }
          // Verifica se o token de refresh expirou
          if (token.expiredAt < new Date()) {
            return res.status(401).json({ error: "Refresh token expired" });
          }
          // Verifica se o usuário existe
          const userExists = await prisma.user.findUnique({
            where: {
              id: token.userId,
            },
          });

          // Se o usuário não existir, retorna erro 401
          if (!userExists) {
            return res.status(401).json({ error: "User not found" });
          }

          // Gera um novo token de acesso
          const newAccessToken = jwt.sign(
            {
              id: userExists.id,
              username: userExists.username,
              email: userExists.email,
            },
            ACCESS_TOKEN_SECRET,
            { expiresIn: ACCESS_TOKEN_EXPIRY }
          );

          // Atualiza o token de refresh no banco de dados
          await prisma.token.update({
            where: {
              id: token.id,
            },
            data: {
              access: newAccessToken,
              expiredAt: new Date(Date.now() + 1 * 24 * 60 * 60 * 1000), // 1 dia
            },
          });

          // Retorna o novo token de acesso
          res.json({ accessToken: newAccessToken });
        }
      )
    : res.status(401).json({ error: "Refresh token not provided" });
});

// Endpoint para revogar o token de acesso
app.post("/api/revoke", async (req: Request, res: Response) => {
  /**
   * @swagger
   * /api/revoke:
   *   post:
   *     summary: Revoga um token de refresh
   *     tags: [Autenticação]
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               refreshToken:
   *                 type: string
   *                 description: Token de refresh JWT a ser revogado
   *             required:
   *               - refreshToken
   *     responses:
   *       200:
   *         description: Token revogado com sucesso
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 message:
   *                   type: string
   *                   example: Refresh token revoked
   *       401:
   *         description: Token de refresh não fornecido, não encontrado, já revogado ou expirado
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   example: Refresh token not provided
   *       403:
   *         description: Token de refresh inválido
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   example: Invalid refresh token
   */
  // Obter o token de refresh do corpo da requisição
  const { refreshToken } = req.body;

  // Verifica se o token de refresh foi enviado
  refreshToken
    ? // Verifica se o token de refresh é válido
      jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, async (err: any) => {
        // Se o token de refresh for inválido, retorna erro 403
        if (err) {
          return res.status(403).json({ error: "Invalid refresh token" });
        }

        // Verifica se o token de refresh está na lista de tokens e não foi revogado
        const token = await prisma.token.findFirst({
          where: {
            refresh: refreshToken,
            revoked: false,
            expiredAt: {
              gt: new Date(),
            },
          },
        });

        // Se o token de refresh não existir, retorna erro 401
        if (!token) {
          return res.status(401).json({ error: "Refresh token not found" });
        }

        // Verifica se o token de refresh foi revogado
        if (token.revoked) {
          return res.status(401).json({ error: "Refresh token revoked" });
        }

        // Verifica se o token de refresh expirou
        if (token.expiredAt < new Date()) {
          return res.status(401).json({ error: "Refresh token expired" });
        }

        // Revoga o token de refresh no banco de dados
        await prisma.token.update({
          where: {
            id: token.id,
          },
          data: {
            revoked: true,
          },
        });
        // Retorna mensagem de sucesso
        res.json({ message: "Refresh token revoked" });
      })
    : // Se o token de refresh não foi enviado, retorna erro 401
      res.status(401).json({ error: "Refresh token not provided" });
});

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
