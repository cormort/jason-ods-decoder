// 在背景執行緒載入 Pyodide 與解碼器，避免解碼時畫面卡住。
// 檔案內容只在瀏覽器記憶體中處理，不會傳到任何伺服器。
// 執行環境自架：所有檔案都在本站 ./pyodide/ 底下，不連任何外部 CDN。
importScripts('./pyodide/pyodide.js');

let pyodide = null;
let decodeOne = null;

async function init() {
  pyodide = await loadPyodide({ indexURL: './pyodide/' });
  await pyodide.loadPackage('numpy');
  const resp = await fetch('decoder.py');
  if (!resp.ok) throw new Error('無法載入 decoder.py: HTTP ' + resp.status);
  const src = await resp.text();
  pyodide.FS.writeFile('/home/pyodide/ods_batch.py', src);
  pyodide.runPython(`
import sys
sys.path.insert(0, '/home/pyodide')
import numpy as np
import ods_batch
ods_batch.np = np
ods_batch._ensure_tables()
_cache = set()   # 同一批同範本檔案共用種子快取，第二份起會快很多

import json

def decode_one(buf):
    data = buf.to_bytes()
    codes, status = ods_batch.decode_status(data, cache=_cache)
    if not codes:
        return status, '', 0, '[]'
    n = sum(1 for c in codes if c != ods_batch.PARA)
    paras = [{'text': p['text'], 'first': p['first'], 'rest': p['rest']}
             for p in ods_batch.paragraphs(codes)]
    return status, ods_batch.render(codes) + '\\r\\n', n, json.dumps(paras, ensure_ascii=False)
`);
  decodeOne = pyodide.globals.get('decode_one');
}

const ready = init().then(
  () => postMessage({ type: 'ready' }),
  (e) => postMessage({ type: 'fatal', error: String(e) })
);

onmessage = async (ev) => {
  const { id, bytes } = ev.data;
  await ready;
  const t0 = performance.now();
  let res = null;
  try {
    res = decodeOne(bytes);
    const [status, text, chars, parasJson] = res.toJs();
    postMessage({ type: 'result', id, status, text, chars, paras: JSON.parse(parasJson), ms: performance.now() - t0 });
  } catch (e) {
    postMessage({ type: 'result', id, status: 'error', text: '', chars: 0, paras: [], error: String(e), ms: performance.now() - t0 });
  } finally {
    if (res) res.destroy();
  }
};
