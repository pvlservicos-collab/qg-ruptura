// GET    /api/login  → 200 { logado: true }  |  401 { logado: false }
// POST   /api/login  → body { senha } → 200 { ok: true } + cookie  |  401 { ok: false, erro }
// PUT    /api/login  → body { atual, nova } (logado) → 200 { ok: true } + cookie novo  |  400/401/503 { ok: false, erro }
// DELETE /api/login  → apaga o cookie
import { criarCookie, cookieSair, lerSessao, json, naoAutorizado } from '../../lib/sessao.js';
import { conferirSenha, mudarSenha, temSenha } from '../../lib/senha.js';

const freio = () => new Promise(r => setTimeout(r, 600)); // freia tentativa e erro

async function lerCorpo(request) {
  try { return await request.json(); } catch { return {}; }
}

async function tratar(request) {
  if (request.method === 'GET') return lerSessao(request) ? json({ logado: true }) : naoAutorizado();

  if (request.method === 'POST') {
    const corpo = await lerCorpo(request);
    if (!(await conferirSenha(corpo.senha))) {
      await freio();
      if (!(await temSenha())) return json({ ok: false, erro: 'O servidor está sem senha: falta RUPTURA_SENHA nas variáveis de ambiente (depois de adicionar, faça um Redeploy).' }, 500);
      return json({ ok: false, erro: 'Senha incorreta.' }, 401);
    }
    return json({ ok: true }, 200, { 'Set-Cookie': criarCookie() });
  }

  if (request.method === 'PUT') {
    if (!lerSessao(request)) return naoAutorizado();
    const corpo = await lerCorpo(request);
    if (!(await conferirSenha(corpo.atual))) {
      await freio();
      return json({ ok: false, erro: 'A senha atual não confere.' }, 401);
    }
    if (String(corpo.nova || '').trim() === String(corpo.atual || '').trim()) return json({ ok: false, erro: 'A senha nova é igual à atual.' }, 400);
    try {
      await mudarSenha(corpo.nova);
    } catch (e) {
      return json({ ok: false, erro: e.message }, e.status || 500);
    }
    return json({ ok: true }, 200, { 'Set-Cookie': criarCookie() });
  }

  if (request.method === 'DELETE') return json({ ok: true }, 200, { 'Set-Cookie': cookieSair });
  return json({ erro: 'Método não permitido.' }, 405);
}

// Qualquer erro de configuração volta como JSON legível, em vez de uma página 500 que o site não sabe mostrar.
export default async (request) => {
  try {
    return await tratar(request);
  } catch (e) {
    console.error('login:', e);
    return json({ ok: false, erro: e.message || 'Erro no servidor.' }, 500);
  }
};

export const config = { path: '/api/login' };
