/**
 * ATOS 飞书数据代理 - Cloudflare Worker
 */

const TABLE_MAP = {
  members:       'tblvbL0LEaVTq5ig',
  tasks:         'tblaF23BikiQa01s',
  okrs:          'tblIJC040MnVevVy',
  krs:           'tblIJC040MnVevVy',  // KR 与 OKR 共用一张表
  tickets:       'tbleV0yfyxKoOjrx',
  blockages:     'tbl35IX8wvwa7Whu',
  dispatches:    'tblQuLBcmTMpxtgN',
  prompts:       'tblYzoHUwXjbY6yJ',
  tools:         'tblpxLuRs7G2UKbj',
  arbitrations:  'tbljC3GJawCibXOR',  // 仲裁记录表
  followups:     'tbl3j6D1eUzjLwxn',  // 催办记录表
  submissions:   'tblgGPWzspcs3Ivg',  // 提交记录表
};

const FEISHU = 'https://open.feishu.cn/open-apis';
const BITABLE = 'Zd90bzqGXafgAFs2ltZc4nzIn4b';
const MEMBERS_TABLE = 'tblvbL0LEaVTq5ig';

// JWT 签发：从 Cloudflare Worker secret 读取（fallback 仅供本地 dev）
const FALLBACK_JWT_SECRET = 'dev-only-do-not-use-in-prod';
const getJwtSecret = (env) => env.JWT_SECRET || FALLBACK_JWT_SECRET;

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

// Token 缓存（Worker 实例级别）
let _token = null;
let _expireAt = 0;

async function getToken(env) {
  if (_token && Date.now() < _expireAt - 60000) return _token;
  const res = await fetch(`${FEISHU}/auth/v3/tenant_access_token/internal`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      app_id: env.FEISHU_APP_ID,
      app_secret: env.FEISHU_APP_SECRET,
    }),
  });
  const data = await res.json();
  _token = data.tenant_access_token;
  _expireAt = Date.now() + data.expire * 1000;
  return _token;
}

function normalizeValue(val) {
  if (val === null || val === undefined) return null;
  if (typeof val === 'number' || typeof val === 'boolean') return val;
  if (typeof val === 'string') return val;
  if (Array.isArray(val)) {
    if (!val.length) return '';
    if (val[0]?.name !== undefined && val[0]?.id !== undefined) return val.map(v => v.name);
    if (val[0]?.text !== undefined) return val.map(v => v.text ?? '').join('');
    return val;
  }
  if (typeof val === 'object') {
    if (val.name !== undefined) return val.name;
    if (val.text !== undefined) return val.text;
  }
  return val;
}

function normalizeRecord(record) {
  const fields = {};
  for (const [k, v] of Object.entries(record.fields || {})) {
    fields[k] = normalizeValue(v);
  }
  return { id: record.record_id, ...fields };
}

async function listAll(tableId, token) {
  const records = [];
  let pageToken = null;
  do {
    const url = new URL(`${FEISHU}/bitable/v1/apps/${BITABLE}/tables/${tableId}/records`);
    url.searchParams.set('page_size', '100');
    if (pageToken) url.searchParams.set('page_token', pageToken);
    const res = await fetch(url.toString(), { headers: { Authorization: `Bearer ${token}` } });
    const data = await res.json();
    if (data.code !== 0) throw new Error(data.msg);
    records.push(...(data.data?.items || []));
    pageToken = data.data?.has_more ? data.data.page_token : null;
  } while (pageToken);
  return records.map(normalizeRecord);
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

// ───────── JWT（HS256，Web Crypto 实现） ─────────
const b64url = {
  enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  dec: (s) => {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return Uint8Array.from(atob(s), c => c.charCodeAt(0));
  },
};
const enc = new TextEncoder();

async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function signJwt(payload, secret, expiresInSec = 86400 * 7) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const body = { ...payload, iat: now, exp: now + expiresInSec };
  const h = b64url.enc(enc.encode(JSON.stringify(header)));
  const b = b64url.enc(enc.encode(JSON.stringify(body)));
  const data = `${h}.${b}`;
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return `${data}.${b64url.enc(sig)}`;
}

async function verifyJwt(token, secret) {
  try {
    const [h, b, s] = token.split('.');
    if (!h || !b || !s) return null;
    const key = await hmacKey(secret);
    const ok = await crypto.subtle.verify('HMAC', key, b64url.dec(s), enc.encode(`${h}.${b}`));
    if (!ok) return null;
    const payload = JSON.parse(new TextDecoder().decode(b64url.dec(b)));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

// ───────── 飞书 OAuth ─────────
const AUTHORIZE_URL = 'https://open.feishu.cn/open-apis/authen/v1/authorize';
const ACCESS_TOKEN_URL = 'https://open.feishu.cn/open-apis/authen/v2/oauth/token';
const USER_INFO_URL = 'https://open.feishu.cn/open-apis/authen/v1/user_info';

async function exchangeCodeForUser(env, code, redirectUri) {
  // 1. code → user_access_token
  const tokenRes = await fetch(ACCESS_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      client_id: env.FEISHU_APP_ID,
      client_secret: env.FEISHU_APP_SECRET,
      code,
      redirect_uri: redirectUri,
    }),
  });
  const tokenData = await tokenRes.json();
  if (tokenData.code !== 0 && !tokenData.access_token) throw new Error(tokenData.error_description || tokenData.msg || 'token交换失败');
  const userAccessToken = tokenData.access_token || tokenData.data?.access_token;

  // 2. user_access_token → 用户信息
  const infoRes = await fetch(USER_INFO_URL, {
    headers: { Authorization: `Bearer ${userAccessToken}` },
  });
  const infoData = await infoRes.json();
  if (infoData.code !== 0) throw new Error(infoData.msg || '获取用户信息失败');
  return infoData.data; // { open_id, name, avatar_url, email, en_name, ... }
}

/** 用 open_id 查 members 表；如果匹配不到，就用姓名 fallback，匹配到后自动把 open_id 写回 */
async function findOrBindMember(appToken, feishuUser) {
  // 先用 open_id 精准查
  const filterUrl = new URL(`${FEISHU}/bitable/v1/apps/${BITABLE}/tables/${MEMBERS_TABLE}/records`);
  filterUrl.searchParams.set('filter', `CurrentValue.[open_id]="${feishuUser.open_id}"`);
  filterUrl.searchParams.set('page_size', '5');
  let res = await fetch(filterUrl.toString(), { headers: { Authorization: `Bearer ${appToken}` } });
  let data = await res.json();
  let items = data.data?.items || [];
  if (items.length) return normalizeRecord(items[0]);

  // 用姓名 fallback + 自动写 open_id
  const nameUrl = new URL(`${FEISHU}/bitable/v1/apps/${BITABLE}/tables/${MEMBERS_TABLE}/records`);
  nameUrl.searchParams.set('filter', `CurrentValue.[姓名]="${feishuUser.name}"`);
  res = await fetch(nameUrl.toString(), { headers: { Authorization: `Bearer ${appToken}` } });
  data = await res.json();
  items = data.data?.items || [];
  if (!items.length) return null;

  const record = items[0];
  // 自动绑定 open_id + 头像
  await fetch(`${FEISHU}/bitable/v1/apps/${BITABLE}/tables/${MEMBERS_TABLE}/records/${record.record_id}`, {
    method: 'PUT',
    headers: { Authorization: `Bearer ${appToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      fields: {
        open_id: feishuUser.open_id,
        ...(feishuUser.avatar_url ? { 头像URL: feishuUser.avatar_url } : {}),
        ...(feishuUser.email ? { 邮箱: feishuUser.email } : {}),
      },
    }),
  });
  return normalizeRecord({ ...record, fields: { ...record.fields, open_id: feishuUser.open_id } });
}

/** 通过 member_id（飞书 record_id）或姓名查 open_id */
async function resolveOpenId(appToken, { member_id, name }) {
  if (member_id) {
    // 直接用 record_id 查
    const res = await fetch(
      `${FEISHU}/bitable/v1/apps/${BITABLE}/tables/${MEMBERS_TABLE}/records/${member_id}`,
      { headers: { Authorization: `Bearer ${appToken}` } },
    );
    const data = await res.json();
    if (data.code === 0) {
      const rec = normalizeRecord(data.data.record);
      if (rec.open_id) return rec.open_id;
    }
  }
  if (name) {
    const url = new URL(`${FEISHU}/bitable/v1/apps/${BITABLE}/tables/${MEMBERS_TABLE}/records`);
    url.searchParams.set('filter', `CurrentValue.[姓名]="${name}"`);
    url.searchParams.set('page_size', '5');
    const res = await fetch(url.toString(), { headers: { Authorization: `Bearer ${appToken}` } });
    const data = await res.json();
    const items = data.data?.items || [];
    if (items.length) {
      const rec = normalizeRecord(items[0]);
      if (rec.open_id) return rec.open_id;
    }
  }
  return null;
}

/** 调用飞书 IM API 发文本卡片（带 link 时用 post 富文本，否则纯文本） */
async function sendFeishuMessage(appToken, openId, text, { link, source } = {}) {
  let msgType = 'text';
  let content;

  if (link) {
    // 富文本（post）：标题 + 正文 + 链接
    msgType = 'post';
    const lines = [];
    if (source) lines.push([{ tag: 'text', text: `【${source}】`, style: ['bold'] }]);
    lines.push([{ tag: 'text', text }]);
    lines.push([{ tag: 'a', text: '点击查看 →', href: link }]);
    content = JSON.stringify({
      zh_cn: { title: source || 'ATOS 通知', content: lines },
    });
  } else {
    content = JSON.stringify({ text: source ? `【${source}】${text}` : text });
  }

  const res = await fetch(`${FEISHU}/im/v1/messages?receive_id_type=open_id`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${appToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      receive_id: openId,
      msg_type: msgType,
      content,
    }),
  });
  const data = await res.json();
  if (data.code !== 0) throw new Error(`飞书 IM 发送失败: ${data.msg} (code=${data.code})`);
  return { message_id: data.data?.message_id };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const parts = url.pathname.replace(/^\/api\//, '').split('/');
    const tableName = parts[0];
    const recordId = parts[1];

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    // 健康检查
    if (url.pathname === '/health') {
      return json({ status: 'ok', tables: Object.keys(TABLE_MAP) });
    }

    // ───────── /auth/* ─────────
    // GET /auth/feishu/login?redirect=<frontend-callback-url>
    // 生成飞书授权 URL，前端直接跳转过去
    if (url.pathname === '/auth/feishu/login') {
      const redirect = url.searchParams.get('redirect') || 'https://atos-portal.pages.dev/auth/callback';
      const state = url.searchParams.get('state') || '';
      const authUrl = new URL(AUTHORIZE_URL);
      authUrl.searchParams.set('app_id', env.FEISHU_APP_ID);
      authUrl.searchParams.set('redirect_uri', redirect);
      authUrl.searchParams.set('state', state);
      return Response.redirect(authUrl.toString(), 302);
    }

    // POST /auth/feishu/callback  { code }
    // 前端拿到 code 后 POST 过来换 JWT
    if (url.pathname === '/auth/feishu/callback' && request.method === 'POST') {
      try {
        const { code, redirect_uri } = await request.json();
        if (!code) return json({ error: '缺少 code' }, 400);
        const feishuUser = await exchangeCodeForUser(env, code, redirect_uri);
        const appToken = await getToken(env);
        const member = await findOrBindMember(appToken, feishuUser);
        if (!member) {
          return json({
            error: '未找到成员',
            detail: `飞书用户「${feishuUser.name}」不在 members 表。请先联系管理员把你加入系统。`,
            feishu_user: { name: feishuUser.name, open_id: feishuUser.open_id },
          }, 403);
        }
        const token = await signJwt({
          sub: member.id,
          open_id: feishuUser.open_id,
          name: member['姓名'] || feishuUser.name,
          role: member['角色'] || '',
        }, getJwtSecret(env));
        return json({
          token,
          user: {
            member_id: member.id,
            open_id: feishuUser.open_id,
            name: member['姓名'] || feishuUser.name,
            role: member['角色'] || '',
            avatar_url: feishuUser.avatar_url || member['头像URL'] || '',
            email: feishuUser.email || member['邮箱'] || '',
          },
        });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // GET /auth/me  （Authorization: Bearer <token>）
    if (url.pathname === '/auth/me') {
      const auth = request.headers.get('Authorization') || '';
      const token = auth.replace(/^Bearer\s+/i, '');
      const payload = await verifyJwt(token, getJwtSecret(env));
      if (!payload) return json({ error: '未登录或 token 失效' }, 401);
      return json({ user: payload });
    }

    // ───────── /api/notify ─────────
    // POST body: { open_id?, member_id?, name?, text, link?, source? }
    // 必须带至少一个目标字段。优先级：open_id > member_id > name
    if (url.pathname === '/api/notify' && request.method === 'POST') {
      try {
        const body = await request.json();
        const { open_id, member_id, name, text, link, source } = body || {};
        if (!text) return json({ error: '缺少 text' }, 400);

        const appToken = await getToken(env);
        let targetOpenId = open_id;

        // 兜底解析 open_id
        if (!targetOpenId && (member_id || name)) {
          targetOpenId = await resolveOpenId(appToken, { member_id, name });
        }
        if (!targetOpenId) {
          return json({ error: '无法定位接收人 open_id', hint: '请确认 members 表对应成员已绑定 open_id' }, 404);
        }

        const result = await sendFeishuMessage(appToken, targetOpenId, text, { link, source });
        return json({ ok: true, message_id: result.message_id });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    const tableId = TABLE_MAP[tableName];
    if (!tableId) return json({ error: '未知表名' }, 404);

    try {
      const token = await getToken(env);
      const feishuUrl = `${FEISHU}/bitable/v1/apps/${BITABLE}/tables/${tableId}/records`;

      // GET 列表
      if (request.method === 'GET' && !recordId) {
        const records = await listAll(tableId, token);
        return json({ data: records, total: records.length });
      }

      // GET 单条
      if (request.method === 'GET' && recordId) {
        const res = await fetch(`${feishuUrl}/${recordId}`, { headers: { Authorization: `Bearer ${token}` } });
        const data = await res.json();
        if (data.code !== 0) return json({ error: data.msg }, 400);
        return json({ data: normalizeRecord(data.data.record) });
      }

      // POST 新建
      if (request.method === 'POST') {
        const body = await request.json();
        const res = await fetch(feishuUrl, {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields: body }),
        });
        const data = await res.json();
        if (data.code !== 0) return json({ error: data.msg }, 400);
        return json({ data: normalizeRecord(data.data.record) });
      }

      // PATCH 更新
      if (request.method === 'PATCH' && recordId) {
        const body = await request.json();
        const res = await fetch(`${feishuUrl}/${recordId}`, {
          method: 'PUT',
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ fields: body }),
        });
        const data = await res.json();
        if (data.code !== 0) return json({ error: data.msg }, 400);
        return json({ data: normalizeRecord(data.data.record) });
      }

      // DELETE
      if (request.method === 'DELETE' && recordId) {
        const res = await fetch(`${feishuUrl}/${recordId}`, {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = await res.json();
        if (data.code !== 0) return json({ error: data.msg }, 400);
        return json({ success: true });
      }

      return json({ error: 'Not found' }, 404);
    } catch (e) {
      return json({ error: e.message }, 500);
    }
  },
};
