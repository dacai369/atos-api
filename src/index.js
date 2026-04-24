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
  arbitrations:  'tblIJC040MnVevVy',  // 仲裁记录表（临时与 OKR 共用）
  followups:     'tblaF23BikiQa01s',  // 催办记录表（临时与 tasks 共用）
  submissions:   'tblaF23BikiQa01s',  // 提交记录表（临时与 tasks 共用）
};

const FEISHU = 'https://open.feishu.cn/open-apis';
const BITABLE = 'Zd90bzqGXafgAFs2ltZc4nzIn4b';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
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
