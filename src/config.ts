export const JWT_SECRET = process.env.JWT_SECRET || "sua_chave_secreta_aqui"; // Use variáveis de ambiente em produção!
export const JWT_EXPIRES_IN = "1h"; // Token expira em 1 hora
export const REFRESH_TOKEN_SECRET =
  process.env.REFRESH_TOKEN_SECRET || "chave_refresh_secreta";
export const REFRESH_TOKEN_EXPIRES_IN = "7d"; // Refresh token expira em 7 dias
