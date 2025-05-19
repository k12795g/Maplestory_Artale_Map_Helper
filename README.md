# Maplestory_Artale_Map_Helper

**簡介**

* 即時監控 TCP 32800 端口的遊戲頻道玩家列表
* 中文/韓文地圖與職業對照
* 可搜尋並勾選關注地圖，自動存取設定並提醒

## 系統需求

* Python 3.9+（從原始碼執行時）
* 或 Windows/macOS/Linux 執行檔（不需安裝 Python）

## 安裝與執行

**原始碼執行**

```bash
git clone https://github.com/你的帳號/專案.git
cd 專案
pip install scapy
python monitor.py
```

**執行檔使用**

1. 下載並放置 `monitor.exe`、`korean_chinese.json`、`watched_maps.json` 同一資料夾
2. 雙擊 `monitor.exe`

## 設定檔說明

* `korean_chinese.json`：中文／韓文地圖與職業對照
* `watched_maps.json`：儲存關注地圖的韓文列表（首次執行會自動建立）

## 授權

採用 MIT License，詳見 LICENSE。
