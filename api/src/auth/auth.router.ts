// Les routes de l'authentification : s'inscrire, se connecter, savoir qui je suis.
import {response, Router} from 'express';
import { HttpError } from '../errors.js';
import { requireAuth } from '../middlewares/requireAuth.js';
import { validate } from '../middlewares/validate.js';
import {hashPassword, signAccessToken, verifyPassword} from './auth.service.js';
import { users } from './user.repository.js';
import { LoginSchema, RegisterSchema, type Credentials } from './user.schema.js';
import {toPublic} from  './user.schema.js';
import bcrypt from "bcryptjs";

export const authRouter = Router();

// POST /api/auth/register { email, password } → 201 l'utilisateur créé
// DEUX défauts. Trouvez-les : l'un se voit dans Swagger, l'autre avec make db-shell.
authRouter.post('/register', validate(RegisterSchema), async (req, res) => {
  const { email, password } = req.body as Credentials;
  const user = await users.insert({ email, password: await hashPassword(password) });
  const publicUser = await toPublic(user);
  res.status(201).json(publicUser);
});

// POST /api/auth/login { email, password } → 200 { accessToken, tokenType: 'Bearer', expiresIn }
// TODO 3 (TD JWT, étape 2) : retrouver l'utilisateur par son email, vérifier le mot de passe,
// signer un jeton. Email inconnu ou mot de passe faux → le MÊME 401 'Invalid credentials' (on ne dit pas lequel).
authRouter.post('/login', validate(LoginSchema), async (_req, _res) => {
  const { email, password } = _req.body as Credentials;
  const toBecheckedAgainst = await users.findByEmail(email);

  if (!toBecheckedAgainst || !(await verifyPassword(password, toBecheckedAgainst.password))){
    throw new HttpError(401, 'Invalid credentials');
  }

  const {accessToken, expiresIn } = signAccessToken(toBecheckedAgainst);

  response.json({accessToken, tokenType: 'Bearer', expiresIn})
});

// GET /api/auth/me (protégée) → 200 { id, email } : l'utilisateur du jeton
// TODO 5 (TD JWT, étape 3) : renvoyer res.locals.user, déposé par requireAuth.
authRouter.get('/me', requireAuth, async (_req, _res) => {
  throw new HttpError(501, 'Not Implemented');
});
