const { getToken, listAll, normalizeRecord, TABLE_MAP, BASE, BITABLE } = require('./_feishu');

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export default async function handler(req, res) {
  // OPTIONS preflight
  if (req.method === 'OPTIONS') return res.status(200).setHeader(Object.keys(CORS)[0], CORS['Access-Control-Allow-Origin']).end();
  Object.entries(CORS).forEach(([k, v]) => res.setHeader(k, v));

  const { table } = req.query;
  const tableId = TABLE_MAP[table];
  if (!tableId) return res.status(404).json({ error: '未知表名' });

  try {
    const token = await getToken();

    // GET → 列表
    if (req.method === 'GET') {
      const records = await listAll(tableId);
      return res.json({ data: records, total: records.length });
    }

    // POST → 新建
    if (req.method === 'POST') {
      const r = await fetch(`${BASE}/bitable/v1/apps/${BITABLE}/tables/${tableId}/records`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: req.body }),
      });
      const data = await r.json();
      if (data.code !== 0) return res.status(400).json({ error: data.msg });
      return res.json({ data: normalizeRecord(data.data.record) });
    }

    res.status(405).json({ error: 'Method not allowed' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}
