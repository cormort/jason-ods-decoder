// 在背景執行緒載入 Pyodide 與解碼器，避免解碼時畫面卡住。
// 檔案內容只在瀏覽器記憶體中處理，不會傳到任何伺服器。
importScripts('https://cdn.jsdelivr.net/pyodide/v0.26.4/full/pyodide.js');

let pyodide = null;

async function init() {
  pyodide = await loadPyodide();
  await pyodide.loadPackage('numpy');
  const src = await (await fetch('decoder.py')).text();
  pyodide.FS.writeFile('/home/pyodide/ods_batch.py', src);
  pyodide.runPython(`
import sys
sys.path.insert(0, '/home/pyodide')
import numpy as np
import ods_batch
ods_batch.np = np
ods_batch._ensure_tables()
_cache = set()   # 同一批同範本檔案共用種子快取，第二份起會快很多

def decode_one(buf):
    data = buf.to_bytes()
    codes, status = ods_batch.decode_status(data, cache=_cache)
    if not codes:
        return status, '', 0
    n = sum(1 for c in codes if c != ods_batch.PARA)
    return status, ods_batch.render(codes) + '\\r\\n', n
`);
}

const ready = init().then(
  () => postMessage({ type: 'ready' }),
  (e) => postMessage({ type: 'fatal', error: String(e) })
);

onmessage = async (ev) => {
  const { id, bytes } = ev.data;
  await ready;
  const t0 = performance.now();
  try {
    const fn = pyodide.globals.get('decode_one');
    const res = fn(bytes);
    const [status, text, chars] = res.toJs();
    res.destroy();
    fn.destroy();
    postMessage({ type: 'result', id, status, text, chars, ms: performance.now() - t0 });
  } catch (e) {
    postMessage({ type: 'result', id, status: 'error', text: '', chars: 0, error: String(e), ms: performance.now() - t0 });
  }
};
