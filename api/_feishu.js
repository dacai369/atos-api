/**
 * 飞书 Token 管理模块（Vercel 环境变量读取）
 */

const APP_ID     = process.env.FEISHU_APP_ID     || 'cli_a962c4d0aabb5cd3';
const APP_SECRET = process.env.FEISHU_APP_SECRET  || 'yEePIwq85wiqHoTasGrs2c1KfPUWbbw1';
const BITABLE    = process.env.FEISHU_BITABLE     || 'Zd90bzqGXafgAFs2ltZc4nzIn4b';
const BASE       = 'https://open.feishu.cn/open-apis';

const TABLE_MAP = {
  members:    'tblvbL0LEaVTq5ig',
  tasks:      'tblaF23BikiQa01s',
  okrs:       'tblIJC040MnVevVy',
  tickets:    'tbleV0yfyxKoOjrx',
  blockages:  'tbl35IX8wvwa7Whu',
  dispatches: 'tblQuLBcmTMpxtgN',
  prompts:    'tblYzoHUwXjbY6yJ',
  tools:      'tblpxLuRs7G2UKbj',
};

let _token = null;
let _expireAt = 0;

async function getToken() {
  if (_token && Date.now() < _expireAt - 60000) return _token;
  const res = await fetch(`${BASE}/auth/v3/tenant_access_token/internal`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ app_id: APP_ID, app_secret: APP_SECRET }),
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

async function listAll(tableId) {
  const token = await getToken();
  const records = [];
  let pageToken = null;
  do {
    const url = new URL(`${BASE}/bitable/v1/apps/${BITABLE}/tables/${tableId}/records`);
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

module.exports = { getToken, listAll, normalizeRecord, TABLE_MAP, BASE, BITABLE };
