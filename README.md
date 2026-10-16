# 捷成公文 ODS 解碼器（網頁版）

讀取「捷成公文系統」（JSODS / ODSVIEW）的 `.ods` 公文檔，取出文字內容另存成 `.txt`。
原廠已停止營運，舊公文無法再用原廠程式開啟，本工具讓這些檔案仍可閱讀。

**線上使用：** https://cormort.github.io/jason-ods-decoder/

## 隱私

解碼完全在瀏覽器內進行（[Pyodide](https://pyodide.org/) 在瀏覽器裡執行 Python），
**檔案不會上傳到任何伺服器**。頁面只會從 CDN 下載 Pyodide／numpy 執行環境與 JSZip。

## 使用方式

1. 開啟上方網址（第一次需下載約 15 MB 執行環境，之後瀏覽器會快取）。
2. 選擇 `.ods` 檔、選擇資料夾，或直接拖曳到頁面上。
3. 逐份「檢視」或「下載」，或按「全部下載（ZIP）」，ZIP 內保留原資料夾結構。

## 說明

- 這裡的 `.ods` 是捷成自訂格式（檔頭 `JASON`），**不是** LibreOffice / OpenDocument 試算表。
  真正的試算表會顯示「非捷成格式」。
- 輸出為公文文字內容（本文；函稿含主旨與說明），不含發文機關、日期、文號等套印欄位與版面。
- 每份約 1–5 秒；大量檔案較適合用桌面版批次處理。

## 檔案

| 檔案 | 用途 |
|---|---|
| `index.html` | 頁面與介面 |
| `worker.js` | 在背景執行緒載入 Pyodide 並解碼 |
| `decoder.py` | 解碼核心（純 Python + numpy，也可在本機直接執行：`python decoder.py 資料夾 輸出資料夾`） |

本機預覽：`python -m http.server` 後開啟 `http://localhost:8000`（Web Worker 無法用 `file://` 開啟）。

本工具與原廠無關，僅供讀取自有的舊公文檔。
