const { getToken, normalizeRecord, TABLE_MAP, BASE, BITABLE } = require('../_feishu');

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,PATCH,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export default async function handler(req, res) {
  if (req.method === 'OPTIONS') return res.status(200).end();
  Object.entries(CORS).forEach(([k, v]) => res.setHeader(k, v));

  const { table, id } = req.query;
  const tableId = TABLE_MAP[table];
  if (!tableId) return res.status(404).json({ error: '未知表名' });

  try {
    const token = await getToken();
    const url = `${BASE}/bitable/v1/apps/${BITABLE}/tables/${tableId}/records/${id}`;

    if (req.method === 'GET') {
      const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
      const data = await r.json();
      if (data.code !== 0) return res.status(400).json({ error: data.msg });
      return res.json({ data: normalizeRecord(data.data.record) });
    }

    if (req.method === 'PATCH') {
      const r = await fetch(url, {
        method: 'PUT',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields: req.body }),
      });
      const data = await r.json();
      if (data.code !== 0) return res.status(400).json({ error: data.msg });
      return res.json({ data: normalizeRecord(data.data.record) });
    }

    if (req.method === 'DELETE') {
      const r = await fetch(url, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } });
      const data = await r.json();
      if (data.code !== 0) return res.status(400).json({ error: data.msg });
      return res.json({ success: true });
    }

    res.status(405).json({ error: 'Method not allowed' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}
