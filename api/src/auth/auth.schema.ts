import { z } from 'zod';


export const RefreshSchema = z.object({
  refreshToken: z.string().regex(/^[0-9a-f]{64}$/)
});
export type RefreshInput = z.infer<typeof RefreshSchema>;
