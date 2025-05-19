import os
import re
import json
import tkinter as tk
from tkinter import scrolledtext, ttk
from scapy.all import AsyncSniffer, TCP

class ChannelMonitorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("頻道玩家監控")
        self.geometry("900x650")

        # 載入對照表
        mapping = json.load(open('korean_chinese.json', 'r', encoding='utf-8'))
        self.job_map = mapping['職業對照']
        self.map_map = mapping['地圖對照']  # { 韓文: 中文 }

        # 建立 (中文, 韓文) 列表並排序：先依中文，後把「待定」擺最後
        self.all_map_items = [
            (zh, kr) for kr, zh in self.map_map.items()
        ]
        self._sort_map_items()

        # BooleanVar 儲存每個地圖的勾選狀態
        self.checkbox_vars = {
            item: tk.BooleanVar(value=False) for item in self.all_map_items
        }

        # 讀取上次儲存的韓文關注地圖
        self.watched_maps_file = 'watched_maps.json'
        self.watched_maps_kr = set()   # 儲存韓文
        self.watched_maps_zh = set()   # 對應中文，用於顯示＆比對
        if os.path.exists(self.watched_maps_file):
            try:
                self.watched_maps_kr = set(json.load(open(self.watched_maps_file, 'r', encoding='utf-8')))
            except:
                self.watched_maps_kr = set()
        # 根據已儲存的韓文，把對應的 checkbox 打勾
        for (zh, kr), var in self.checkbox_vars.items():
            if kr in self.watched_maps_kr:
                var.set(True)
                self.watched_maps_zh.add(zh)

        self.filtered_map_items = list(self.all_map_items)

        # 封包重組 buffer
        self.data_buffer = b''
        # 多欄顯示預設欄數
        self.COLS = 3

        # 建 UI 並啟動監控
        self._create_widgets()
        self.sniffer = None
        self.start_sniff()

    def _sort_map_items(self):
        # zh == '待定' 排最後，其餘按 zh 排序
        self.all_map_items.sort(key=lambda x: (x[0]=='待定', x[0]))

    def _create_widgets(self):
        top = ttk.Frame(self)
        top.pack(fill='x', padx=5, pady=5)

        # 搜尋框
        ttk.Label(top, text="🔎 搜尋地圖：").pack(anchor='w')
        self.search_var = tk.StringVar()
        self.search_var.trace_add('write', lambda *a: self.filter_maps())
        ttk.Entry(top, textvariable=self.search_var).pack(fill='x', pady=(0,5))

        # 可捲動多欄勾選區
        chk_frame = ttk.Frame(top)
        chk_frame.pack(fill='both', expand=False, pady=(0,5))
        canvas = tk.Canvas(chk_frame, height=200)
        scrollbar = ttk.Scrollbar(chk_frame, orient='vertical', command=canvas.yview)
        self.inner = ttk.Frame(canvas)
        self.inner.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0,0), window=self.inner, anchor='nw')
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        self._populate_checkboxes()

        # 更新按鈕（自動儲存）
        ttk.Button(top, text="✅ 更新關注地圖", command=self.on_update).pack(anchor='e')

        # 狀態燈
        status = ttk.Frame(self)
        status.pack(fill='x', padx=5, pady=(0,5))
        ttk.Label(status, text="監控狀態：").pack(side='left')
        self.status_canvas = tk.Canvas(status, width=20, height=20, highlightthickness=0)
        self.light = self.status_canvas.create_oval(2,2,18,18, fill='red')
        self.status_canvas.pack(side='left')

        # 日誌區
        self.log = scrolledtext.ScrolledText(self, state='disabled', wrap='word')
        self.log.pack(fill='both', expand=True, padx=5, pady=5)

    def _populate_checkboxes(self):
        for w in self.inner.winfo_children():
            w.destroy()
        for idx, (zh, kr) in enumerate(self.filtered_map_items):
            var = self.checkbox_vars[(zh, kr)]
            chk = tk.Checkbutton(
                self.inner,
                text=f"{zh} ({kr})",
                variable=var,
                highlightthickness=0,  # 取消焦點邊框
                bd=0                   # 取消一般邊框
            )
            r, c = divmod(idx, self.COLS)
            chk.grid(row=r, column=c, sticky='w', padx=5, pady=2)
        for c in range(self.COLS):
            self.inner.grid_columnconfigure(c, weight=1)

    def filter_maps(self):
        kw = self.search_var.get().strip().lower()
        if not kw:
            self.filtered_map_items = list(self.all_map_items)
        else:
            self.filtered_map_items = [
                item for item in self.all_map_items
                if kw in item[0].lower() or kw in item[1].lower()
            ]
        self._populate_checkboxes()

    def on_update(self):
        # 重設並蒐集最新的 watched_maps
        self.watched_maps_kr.clear()
        self.watched_maps_zh.clear()
        for (zh, kr), var in self.checkbox_vars.items():
            if var.get():
                self.watched_maps_kr.add(kr)
                self.watched_maps_zh.add(zh)
        # 儲存「韓文」列表
        try:
            with open(self.watched_maps_file, 'w', encoding='utf-8') as f:
                json.dump(list(self.watched_maps_kr), f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.log_message(f"❌ 儲存關注地圖失敗：{e}")
            return
        self.log_message(f"✅ 已更新關注地圖：{', '.join(self.watched_maps_zh) or '（清空）'}")

    def start_sniff(self):
        self.sniffer = AsyncSniffer(
            filter='tcp port 32800', prn=self.process_packet, store=False
        )
        self.sniffer.start()
        self.set_light(True)
        self.log_message("🟢 開始監控 TCP 32800 端口封包…")

    def set_light(self, on: bool):
        color = 'green' if on else 'red'
        self.status_canvas.itemconfig(self.light, fill=color)

    def log_message(self, msg: str):
        self.log.configure(state='normal')
        self.log.insert('end', msg + '\n')
        self.log.yview('end')
        self.log.configure(state='disabled')

    def _add_pending_map(self, kr_map):
        """遇到新韓文地圖時，動態新增到清單、並重新排序與顯示。"""
        new_item = ('待定', kr_map)
        if new_item not in self.all_map_items:
            # 更新 in-memory
            self.map_map[kr_map] = '待定'
            self.checkbox_vars[new_item] = tk.BooleanVar(value=False)
            self.all_map_items.append(new_item)
            self._sort_map_items()
        # 重新套用過濾與勾選列表
        self.filter_maps()

    def process_packet(self, pkt):
        if TCP not in pkt:
            return
        self.data_buffer += bytes(pkt[TCP].payload)
        while True:
            start = self.data_buffer.find(b'TOZ ')
            if start<0 or len(self.data_buffer)<start+8:
                break
            length = int.from_bytes(self.data_buffer[start+4:start+8], 'little')
            if len(self.data_buffer)<start+8+length:
                break
            pkt_bytes = self.data_buffer[start:start+8+length]
            self.data_buffer = self.data_buffer[start+8+length:]

            players = self.extract_channel_players(pkt_bytes)
            if players:
                # 列出玩家
                self.after(0, lambda: self.log_message("==> 抓到頻道內玩家目錄："))
                present = {p['map_zh'] for p in players}
                for p in players:
                    line = (
                        f"暱稱: {p['nickname']:<16}｜"
                        f"ID: {p['id']}｜"
                        f"地圖: {p['map_zh']}｜"
                        f"等級: {p['level']}｜"
                        f"職業: {p['job_zh']}"
                    )
                    self.after(0, lambda l=line: self.log_message(l))

                # 檢查關注地圖是否都有玩家
                if self.watched_maps_zh:
                    missing = self.watched_maps_zh - present
                    if missing:
                        msg = "⚠️ 關注地圖無人： " + "、".join(missing)
                    else:
                        msg = "✅ 所有關注地圖都有玩家"
                    self.after(0, lambda m=msg: self.log_message(m))

                self.after(0, lambda: self.log_message('-'*70))

    def extract_channel_players(self, pkt_bytes):
        if len(pkt_bytes)<8:
            return []
        try:
            text = pkt_bytes[8:].decode('utf-8', errors='ignore')
        except:
            return []
        res = []
        for m in re.finditer(r'(\d{17})', text):
            rest = text[m.end(1):].lstrip('/')
            parts = rest.split('/')
            if len(parts)<7 or '#' not in parts[2]:
                continue
            id1, nick2 = parts[1], parts[2]
            nick, id2 = nick2.split('#',1)
            if id1!=id2:
                continue

            kr_map = parts[3].strip()
            # 若從未見過此韓文地圖，先更新 JSON 檔並動態加入「待定」
            if kr_map not in self.map_map:
                try:
                    with open('korean_chinese.json', 'r+', encoding='utf-8') as f:
                        j = json.load(f)
                        if kr_map not in j['地圖對照']:
                            j['地圖對照'][kr_map] = "待定"
                            f.seek(0); f.truncate()
                            json.dump(j, f, ensure_ascii=False, indent=2)
                            self.log_message(f"🔄 新增未對應地圖：{kr_map} => 待定（請自行編輯 korean_chinese.json）")
                    # 動態在 UI 加入
                    self.after(0, lambda k=kr_map: self._add_pending_map(k))
                except Exception as e:
                    self.log_message(f"❌ 無法更新地圖對照檔：{e}")

            zh_map = self.map_map.get(kr_map, '待定')
            kr_job = parts[6].strip()
            res.append({
                'nickname': nick,
                'id':       id1,
                'map_zh':   zh_map,
                'level':    parts[5].strip(),
                'job_zh':   self.job_map.get(kr_job, kr_job),
            })
        return res

if __name__ == '__main__':
    app = ChannelMonitorApp()
    app.mainloop()
