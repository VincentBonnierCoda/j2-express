// Les deux savoir-faire du matin, sans Express ni SQL : hacher un mot de passe (bcrypt) et
// signer / vérifier un jeton (JWT). Le routeur et le middleware appellent ces fonctions.
import { HttpError } from '../errors.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

/** Ce qu'on sait d'un utilisateur connecté, lu dans son jeton (pas dans la base). */
export interface AuthUser {
  id: number;
  email: string;
}

// ── bcrypt ─────────────────────────────────────────────────────────────────

/**
 * Pour l'instant, le mot de passe est stocké EN CLAIR : c'est le bug que vous corrigez en premier.
 */
export async function hashPassword(password: string): Promise<string> {

  return await bcrypt.hash(password, 10);
}

/**
 * On ne « déchiffre » jamais un hachage : on hache le candidat et on compare (bcrypt.compare le fait).
 */
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
    return await bcrypt.compare(password, hash);
}

// ── JWT ────────────────────────────────────────────────────────────────────

/**
 * TODO 2 (TD JWT, étape 2) : signer un jeton d'accès pour cet utilisateur.
 * Payload : { sub: l'id en chaîne, email } ; secret : process.env.JWT_SECRET ;
 * durée : process.env.JWT_EXPIRES_IN ('1h' par défaut). expiresIn est renvoyé en secondes.
 */
export function signAccessToken(_user: AuthUser): { accessToken: string; expiresIn: number } {
  const expiresIn = 3600;
  const token =  jwt.sign({ sub: String(_user.id), email :_user.email}, process.env.JWT_SECRET!, { algorithm: 'HS256', expiresIn: '1h' });
  return {
    accessToken: token,
    expiresIn
  };
}

/**
 * TODO 2 (TD JWT, étape 3) : vérifier la signature et la date d'expiration, et
 * reconstruire l'AuthUser depuis le payload. Un jeton expiré → HttpError(401, 'Token expired') ;
 * tout autre problème (signature, format) → HttpError(401, 'Invalid token').
 */
export function verifyAccessToken(_token: string): AuthUser {
  const payload = jwt.verify(_token, process.env.JWT_SECRET!, { algorithms: ['HS256'] }) as jwt.JwtPayload;

  if (typeof payload.sub !== 'string' || typeof payload.email !== 'string') {
    throw new Error('Invalid token payload');
  }
  return {
    id: Number(payload.sub),
    email: payload.email
  };

}
