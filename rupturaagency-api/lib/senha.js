// Senha do QG. Enquanto ninguém troca, vale RUPTURA_SENHA (variável de ambiente).
// Depois de trocar pelo site, vale a nova, guardada com scrypt na mesma loja do estado (Supabase na Vercel).
// Esqueceu a senha nova? Apague a linha de chave 'senha' na tabela ruptura_kv e volta a valer RUPTURA_SENHA.
import { scryptSync, randomBytes, timingSafeEqual } from 'node:crypto';
import { loja } from './estado.js';

const CHAVE = 'senha';
const MINIMO = 6;

const gerarHash = (senha, sal) => scryptSync(String(senha), Buffer.from(sal, 'base64'), 32).toString('base64');

function iguais(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));
  return A.length === B.length && timingSafeEqual(A, B);
}

// Lê a senha trocada pelo site. Sem loja configurada (ex.: Vercel sem Supabase), segue só com a variável de ambiente.
async function lerGuardada() {
  try {
    const s = await loja().get(CHAVE, { type: 'json' });
    return s && s.hash && s.sal ? s : null;
  } catch {
    return null;
  }
}

const senhaAmbiente = () => String(process.env.RUPTURA_SENHA || '').trim();

export async function conferirSenha(senha) {
  const digitada = String(senha || '').trim();
  if (!digitada) return false;
  const guardada = await lerGuardada();
  if (guardada) return iguais(gerarHash(digitada, guardada.sal), guardada.hash);
  const amb = senhaAmbiente();
  return !!amb && iguais(amb, digitada);
}

// Diz se existe alguma senha configurada (para dar um erro claro no login).
export async function temSenha() {
  return !!senhaAmbiente() || !!(await lerGuardada());
}

export async function mudarSenha(nova) {
  const n = String(nova || '').trim();
  if (n.length < MINIMO) throw Object.assign(new Error(`A senha nova precisa ter pelo menos ${MINIMO} caracteres.`), { status: 400 });
  const sal = randomBytes(16).toString('base64');
  try {
    await loja().setJSON(CHAVE, { hash: gerarHash(n, sal), sal, em: Date.now() });
  } catch {
    throw Object.assign(new Error('Não consegui guardar a senha nova: o banco (Supabase) não está configurado no servidor.'), { status: 503 });
  }
}
