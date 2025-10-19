#!/usr/bin/env python3
"""
p2p_chat_manual_gui_notify.py
Features added:
- Persistent random port (as before)
- Ping/pong recorded into history as JSON entries
- Limit ping records per-peer to avoid unbounded growth
- GUI menu: clear history, keep last N messages, keep last X days
- Logging to app.log (no silent excepts)
- Optional shared-key "encryption" (XOR + HMAC) for message payloads (NOT TLS; see warnings)
- ping/pong protocol uses JSON responses: {"pong":1,"rtt_ms":123}
"""


# ماژول‌های مورد نیاز برای عملکردهای مختلف برنامه
import socket, threading, json, os, time, platform, logging, hashlib
import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext
from datetime import datetime, timedelta


tk.Font = ("Arial", 11)


# بررسی سیستم‌عامل؛ اگر ویندوز بود، ماژول winsound برای پخش صدای اعلان وارد می‌شود
if platform.system() == "Windows":
    import winsound  # For notification sound

# ------------------- Configuration -------------------
# نام فایل‌هایی که برای ذخیره داده‌ها استفاده می‌شوند
HISTORY_FILE = "chat_history.json"    # فایل ذخیره تاریخچه پیام‌ها
PORT_FILE = f"listen_port_{socket.gethostname()}.txt"       # فایل ذخیره پورت شنود
LOG_FILE = "app.log"   
PEERS_FILE = "peers.json"


# حداکثر تعداد رکوردهای پینگ ذخیره‌شده برای هر کاربر
MAX_PING_RECORDS_PER_PEER = 300

# کلید اشتراکی اختیاری برای رمزنگاری ساده (XOR + HMAC)
# اگر مقدار خالی باشد رمزنگاری انجام نمی‌شود
# ⚠️ هشدار: این روش امنیت کامل TLS را ندارد و فقط برای جلوگیری از شنود ساده در LAN کاربرد دارد
SHARED_KEY = ""  # مثال: "mysecretkey"

# بازه زمانی بین چک کردن آنلاین بودن همتایان (برحسب ثانیه)
CHECK_INTERVAL = 5
# ----------------- End Configuration ------------------

# تنظیمات سیستم لاگ‌گیری برنامه
logger = logging.getLogger("p2pchat")        # ساخت logger مخصوص برنامه
logger.setLevel(logging.DEBUG)              # تعیین سطح لاگ (ثبت همه سطح‌ها)

# ساخت و افزودن FileHandler برای نوشتن لاگ در فایل
fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
fh.setLevel(logging.DEBUG)
fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")  # قالب‌بندی پیام لاگ
fh.setFormatter(fmt)
logger.addHandler(fh)

# ساخت و افزودن StreamHandler برای نمایش لاگ در کنسول
ch = logging.StreamHandler()
ch.setLevel(logging.WARNING)
ch.setFormatter(fmt)
logger.addHandler(ch)

# تابع ساده برای برگرداندن زمان فعلی به صورت رشته‌ای
def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# قفل thread برای کنترل دسترسی هم‌زمان به تاریخچه
history_lock = threading.Lock()

# تابع برای بارگذاری تاریخچه از فایل
def load_history():
    if os.path.exists(HISTORY_FILE):    # بررسی وجود فایل تاریخچه
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)     # خواندن داده JSON و برگرداندن به صورت dict
        except Exception as e:
            logger.exception("Failed to load history file")
    return {}  # اگر فایل نبود یا خطا داد، تاریخچه خالی برمی‌گرداند

def load_peers():
    """بارگذاری لیست آی‌پی‌ها از فایل peers.json"""
    if os.path.exists(PEERS_FILE):
        try:
            with open(PEERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            logger.exception("Failed to load peers file")
    return {}

def save_peers(peers):
    """ذخیره‌ی لیست آی‌پی‌ها در فایل peers.json"""
    try:
        with open(PEERS_FILE, "w", encoding="utf-8") as f:
            json.dump(peers, f, ensure_ascii=False, indent=2)
    except Exception:
        logger.exception("Failed to save peers file")




# تابع برای ذخیره تاریخچه در فایل JSON
def save_history(hist):
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(hist, f, ensure_ascii=False, indent=2)  # ذخیره با فرمت خوانا
    except Exception as e:
        logger.exception("Failed to save history file")

# بارگذاری تاریخچه قبلی (در صورت وجود)
history = load_history()

# تنظیم تعداد روزهایی که تاریخچه نگه‌داری می‌شود
AUTO_CLEAN_DAYS = 30

# پاکسازی خودکار تاریخچه قدیمی‌تر از X روز
try:
    cutoff = datetime.now() - timedelta(days=AUTO_CLEAN_DAYS)   # زمان مرجع حذف
    with history_lock:
        changed = False
        for peer, lst in list(history.items()):  # پیمایش تاریخچه هر کاربر (peer)
            new_lst = []
            for entry in lst:
                try:
                    t = datetime.strptime(entry.get("time"), "%Y-%m-%d %H:%M:%S")
                except Exception:
                    continue
                if t >= cutoff:                  # فقط پیام‌های جدیدتر از cutoff نگه‌داری می‌شوند
                    new_lst.append(entry)
            if len(new_lst) != len(lst):         # اگر چیزی حذف شد
                history[peer] = new_lst
                changed = True
        if changed:                              # در صورت تغییر، ذخیره تاریخچه جدید
            save_history(history)
            logger.info("Auto-cleaned history to last %d days.", AUTO_CLEAN_DAYS)
except Exception:
    logger.exception("Auto-clean history failed")

# تابع ثبت تاریخچه پیام‌ها و پینگ‌ها برای هر همتا (peer)
def record_history(peer, direction, content, entry_type="msg"):
    """
    اضافه کردن یک رکورد تاریخچه برای یک همتا
    - peer: آدرس IP همتا (string)
    - direction: "in" یا "out" (جهت پیام: دریافتی یا ارسالی)
    - content: محتوای پیام
    - entry_type: نوع رکورد ("msg" برای پیام، "ping" برای پینگ)
    """
    try:
        with history_lock:
            # گرفتن لیست رکوردهای مربوط به این همتا یا ساخت لیست جدید
            lst = history.setdefault(peer, [])
            # افزودن رکورد جدید
            lst.append({
                "time": now(),
                "dir": direction,
                "msg": content,
                "type": entry_type
            })
            # اگر نوع رکورد "ping" باشد، تعداد پینگ‌ها را کنترل می‌کنیم
            if entry_type == "ping":
                pings = [i for i in lst if i.get("type") == "ping"]
                if len(pings) > MAX_PING_RECORDS_PER_PEER:
                    # حذف قدیمی‌ترین پینگ‌ها و نگه‌داشتن جدیدها
                    remove_count = len(pings) - MAX_PING_RECORDS_PER_PEER
                    new_lst = []
                    removed = 0
                    for it in lst:
                        if it.get("type") == "ping" and removed < remove_count:
                            removed += 1
                            continue
                        new_lst.append(it)
                    history[peer] = new_lst
            # ذخیره تاریخچه به‌روزشده
            save_history(history)
    except Exception:
        logger.exception("record_history error")
# ----------------- تابع گرفتن IP محلی -----------------
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # کانکت کردن به یک آدرس عمومی بدون ارسال دیتا برای دریافت IP محلی
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        finally:
            s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"

def center_window(window, width=None, height=None, parent=None):
    """
    مرکز کردن پنجره نسبت به parent (در صورت وجود) یا وسط صفحه.
    """
    window.update_idletasks()

    w = width or window.winfo_width() or 400
    h = height or window.winfo_height() or 300

    if parent and parent.winfo_exists():
        parent.update_idletasks()
        px = parent.winfo_rootx()
        py = parent.winfo_rooty()
        pw = parent.winfo_width()
        ph = parent.winfo_height()
        x = int(px + (pw - w) / 2)
        y = int(py + (ph - h) / 2)
    else:
        screen_w = window.winfo_screenwidth()
        screen_h = window.winfo_screenheight()
        x = int((screen_w - w) / 2)
        y = int((screen_h - h) / 2)

    window.geometry(f"{w}x{h}+{x}+{y}")

# ----------------- توابع رمزنگاری ساده با کلید مشترک -----------------

def _key_bytes():
    """برگشت کلید رمزنگاری به صورت بایت. اگر کلید خالی باشد، بایت خالی برمی‌گرداند."""
    return SHARED_KEY.encode("utf-8") if SHARED_KEY else b""


def _xor_encrypt(data_bytes):
    """
    تابع رمزنگاری/رمزگشایی با الگوریتم ساده XOR
    با استفاده از کلید مشترک (key)
    """
    key = _key_bytes()
    if not key:
        # اگر کلید تعریف نشده باشد، داده بدون تغییر برگردانده می‌شود
        return data_bytes
    out = bytearray(len(data_bytes))
    for i, b in enumerate(data_bytes):
        # هر بایت داده با بایت متناظر کلید XOR می‌شود
        out[i] = b ^ key[i % len(key)]
    return bytes(out)

def make_hmac(data_bytes):
    """
    ساخت HMAC ساده با استفاده از SHA-256 برای اطمینان از صحت پیام
    """
    key = _key_bytes()
    if not key:
        return ""
    # ترکیب کلید و داده و محاسبه هش SHA-256
    h = hashlib.sha256(key + data_bytes).hexdigest()
    return h


def pack_payload(obj):
    """
    بسته‌بندی داده برای ارسال:
    - اگر کلید اشتراکی تعریف نشده باشد → فقط JSON عادی برگردانده می‌شود.
    - اگر کلید وجود داشته باشد → داده رمز می‌شود و همراه با HMAC ارسال می‌گردد.
    """
    raw = json.dumps(obj).encode("utf-8")
    if not SHARED_KEY:
        return raw
    enc = _xor_encrypt(raw)
    return json.dumps({
        "enc": 1,  # نشانه اینکه پیام رمزنگاری شده
        "payload": enc.hex(),  # متن رمز شده به صورت hex
        "hmac": make_hmac(enc).lower()  # HMAC برای صحت‌سنجی
    }).encode("utf-8")


def unpack_payload(raw_bytes):
    """
    بازکردن بسته دریافتی:
    - اگر پیام ساده باشد، JSON را مستقیماً برمی‌گرداند.
    - اگر پیام رمز شده باشد، HMAC چک می‌شود و سپس رمزگشایی انجام می‌گیرد.
    """
    try:
        data = raw_bytes.decode("utf-8")
    except Exception:
        raise ValueError("Invalid encoding")
    try:
        obj = json.loads(data)
    except Exception:
        raise ValueError("Not JSON")

    # بررسی اینکه پیام رمز شده است یا نه
    if isinstance(obj, dict) and obj.get("enc") == 1:
        if not SHARED_KEY:
            # اگر پیام رمز شده باشد ولی ما کلید نداشته باشیم
            raise ValueError("Received encrypted payload but no SHARED_KEY configured")
        payload_hex = obj.get("payload", "")
        hmac_recv = obj.get("hmac", "").lower()
        enc = bytes.fromhex(payload_hex)

        # بررسی تطابق HMAC دریافتی با HMAC محاسبه‌شده
        if make_hmac(enc).lower() != hmac_recv:
            raise ValueError("HMAC mismatch")

        # رمزگشایی داده و بازکردن JSON نهایی
        dec = _xor_encrypt(enc)
        return json.loads(dec.decode("utf-8"))
    else:
        return obj


# ----------------- کلاس اصلی رابط کاربری چت -----------------
class ChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Manual LAN Chat")

        # گرفتن IP محلی
        self.local_ip = get_local_ip()
        # راه‌اندازی listener برای دریافت پیام‌ها (تعریف شده در جای دیگر کد)
        self.listen_port = self.start_listener()
        # user-visible name (editable in UI)
        self.my_name = ""   # will be set from the entry below


        # نگهداری لیست همتایان (peers) و پنجره‌های چت باز شده
        self.peers = load_peers()

        self.chat_windows = {}

        # نگهداری IP هایی که پیام جدید دارند (برای ستاره‌دار کردن در لیست)
        self.new_msg_peers = set()

        # راه‌اندازی رابط کاربری
        self.ui_setup()
        self.refresh_peers()

        # به Tkinter فرصت بده تا اندازه واقعی پنجره محاسبه بشه
        self.root.update_idletasks()

        # حالا وسط‌چین کن
        center_window(self.root, 420, 650)

        save_peers(self.peers)


        # راه‌اندازی یک thread برای بررسی آنلاین بودن همتایان
        threading.Thread(target=self.check_peers_online, daemon=True).start()
        self.root.after(5000, self.auto_check_ip)  # هر 5 ثانیه بررسی IP

    def ui_setup(self):
        """
        طراحی رابط کاربری اصلی (لیست کاربران)
        """
        self.root.configure(bg="#e7eefb")

        # نوار عنوان
        title_bar = tk.Frame(self.root, bg="#5b9bd5", height=50)
        title_bar.pack(fill="x")

        tk.Label(
            title_bar,
            text="💬  Manual LAN Chat",
            bg="#5b9bd5",
            fg="white",
            font=("Segoe UI", 13, "bold")
        ).pack(side="left", padx=15, pady=10)

        # قاب اصلی
        frame = tk.Frame(self.root, bg="#e7eefb")
        frame.pack(padx=10, pady=10, fill="both", expand=True)

        # نمایش IP
        self.ip_label = tk.Label(
            frame,
            text=f"Your IP: {self.local_ip}:{self.listen_port}",
            bg="#e7eefb",
            fg="#333",
            font=("Segoe UI", 11, "bold")
        )
        self.ip_label.pack(pady=(0, 10))

        # ----- Name entry under "Your IP" -----
        name_frame = tk.Frame(frame, bg="#e7eefb")
        name_frame.pack(pady=(0, 8), fill="x")

        tk.Label(name_frame, text="Your name:", bg="#e7eefb", fg="#333", font=("Segoe UI", 10)).pack(side="left", padx=(4,6))
        self.entry_name = tk.Entry(name_frame, font=("Segoe UI", 10), width=18, relief="flat")
        self.entry_name.pack(side="left")

        # 🔹 دکمه ذخیره نام
        save_btn = tk.Button(name_frame, text="💾", bg="#5b9bd5", fg="white",
                            font=("Segoe UI", 9, "bold"), relief="flat",
                            command=lambda: _save_name_event())
        save_btn.pack(side="left", padx=(6, 0))

        # load default if you stored it previously in peers under local_ip (optional)
        try:
            self.my_name = self.peers.get(self.local_ip, {}).get("name", "") or ""
            if self.my_name:
                self.entry_name.insert(0, self.my_name)
        except Exception:
            self.my_name = ""

        # save handler: update self.my_name when entry changes (Enter or focus out)
        def _save_name_event(e=None):
            print("Saving name:", self.entry_name.get())
            try:
                self.my_name = self.entry_name.get().strip()
                # optionally persist under local_ip in peers (not required, but helpful)
                try:
                    if self.local_ip:
                        p = self.peers.setdefault(self.local_ip, {})
                        p["name"] = self.my_name
                        if self.local_ip:
                            p = self.peers.setdefault(self.local_ip, {})
                            p["name"] = self.my_name
                            p["port"] = self.listen_port   # ✅ این خط رو اضافه کن
                            save_peers(self.peers)

                        save_peers(self.peers)
                except Exception:
                    logger.debug("Failed to persist local name to peers")
                # refresh UI in case you want to display local name somewhere
                try:
                    self.refresh_peers()
                except Exception:
                    pass
            except Exception:
                logger.exception("Failed to save name from entry")

        # رویدادها برای Enter و خروج از فیلد
        self.entry_name.bind("<Return>", _save_name_event)
        self.entry_name.bind("<KeyRelease-Return>", _save_name_event)  # اضافه‌شده
        self.entry_name.bind("<FocusOut>", _save_name_event)
        # ----------------------------------------


        # فریم لیست کاربران (اصلی)
        self.list_frame = tk.Frame(frame, bg="#ffffff", bd=1, relief="solid")
        self.list_frame.pack(fill="both", expand=True, padx=5, pady=(0, 10))

        # لیست‌باکس
        self.listbox = tk.Listbox(
            self.list_frame,
            width=55,
            height=12,
            font=("Segoe UI", 10),
            bg="#ffffff",
            fg="#000000",
            highlightthickness=0,
            relief="flat",
            selectbackground="#cfe2ff"
        )
        self.listbox.pack(fill="both", expand=True, padx=5, pady=5)
        self.listbox.bind("<Double-Button-1>", self.open_chat_window)

        # فریم دکمه‌ها
        btn_frame = tk.Frame(frame, bg="#e7eefb")
        btn_frame.pack(pady=10)

        tk.Button(
            btn_frame,
            text="Manual Connect",
            command=self.manual_connect,
            bg="#5b9bd5",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padx=10,
            pady=5,
            width=15
        ).pack(side="left", padx=10)

        tk.Button(
            btn_frame,
            text="Refresh",
            command=self.full_refresh,
            bg="#5b9bd5",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padx=10,
            pady=5,
            width=10
        ).pack(side="left", padx=10)

        self.root.title(f"Sanden Chat - {self.local_ip}:{self.listen_port}")

        tk.Button(
            btn_frame,
            text="Test Connection",
            command=self.test_connection,
            bg="#5b9bd5",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            padx=10,
            pady=5,
            width=15
        ).pack(side="left", padx=10)



    def refresh_peers(self):
        """
        نسخه اصلاح‌شده: به‌روزرسانی لیست کاربران و افزودن قابلیت باز کردن چت با دوبار کلیک روی IP
        """
        # پاک کردن ویجت‌های قبلی در فریم
        for widget in self.list_frame.winfo_children():
            widget.destroy()

        # ایجاد ردیف جدید برای هر IP
        for ip, info in self.peers.items():
            # خود سیستم را در لیست نشان نده
            if ip == self.local_ip:
                continue

            row = tk.Frame(self.list_frame, bg="#ffffff")
            row.pack(fill="x", padx=6, pady=3)

            # نقطه‌ی وضعیت (آنلاین / آفلاین)
            color = "green" if info.get("online") else "red"
            canvas = tk.Canvas(row, width=16, height=16, bg="#ffffff", highlightthickness=0)
            canvas.create_oval(3, 3, 13, 13, fill=color, outline=color)
            canvas.pack(side="left", padx=(0, 8))

            # متن IP:Port
            port_str = info.get("port", "")
            name_str = info.get("name", "")
            label_text = f"{ip}:{port_str}"
            if name_str:
                label_text = f"{label_text}  —  {name_str}"
            if ip in self.new_msg_peers:
                label_text = "⭐ " + label_text

            # ساخت لیبل برای نمایش IP
            lbl = tk.Label(
                row,
                text=label_text,
                bg="#ffffff",
                fg="#000000",
                font=("Segoe UI", 10)
            )
            lbl.pack(side="left", padx=2)

            # 👇 افزودن قابلیت دوبارکلیک برای باز کردن چت
            lbl.bind("<Double-Button-1>", lambda e, ip=ip: self.open_chat(ip))

    
    def check_local_ip_change(self):
        """
        بررسی تغییر IP محلی و بروزرسانی در UI و فایل peers
        """
        try:
            current_ip = get_local_ip()
            current_port = self.listen_port

            if current_ip != self.local_ip:
                old_ip = self.local_ip
                self.local_ip = current_ip
                logger.info("Local IP changed: %s -> %s", old_ip, current_ip)

                # بروزرسانی نمایش در UI
                try:
                    self.ip_label.config(text=f"Your IP: {self.local_ip}:{self.listen_port}")
                except Exception:
                    logger.warning("Failed to update IP label in UI")

                # بروزرسانی peers
                if old_ip in self.peers:
                    self.peers.pop(old_ip)
                

                save_peers(self.peers)
                self.refresh_peers()

        except Exception as e:
            logger.warning("Failed to check local IP change: %s", e)


    def full_refresh(self):
        """
        رفرش کامل:
        - بررسی تغییر IP یا پورت
        - بروزرسانی peers
        - رفرش رابط کاربری
        """
        logger.info("Manual refresh triggered")
        self.check_local_ip_change()
        self.refresh_peers()
        self.ip_label.config(text=f"Your IP: {self.local_ip}:{self.listen_port}")



    def auto_check_ip(self):
        self.check_local_ip_change()
        self.root.after(5000, self.auto_check_ip)

    def manual_connect(self):
        """
        افزودن یک همتای جدید به صورت دستی با وارد کردن IP:Port
        """
        txt = simpledialog.askstring("Connect", "Enter IP:Port of peer")
        if not txt:
            return
        try:
            ip, port = txt.split(":")
            port = int(port)
            # افزودن به لیست همتایان
            self.peers[ip] = {"port": port, "online": True}
            self.refresh_peers()
            messagebox.showinfo("Connected", f"Added {ip}:{port}")
            logger.info("User added peer %s:%d", ip, port)
        except Exception as e:
            logger.exception("manual_connect failed")
            messagebox.showerror("Error", "Invalid IP:Port format")
            


    def open_chat_window(self, event=None):
        """
        وقتی کاربر روی یک IP دوبار کلیک کند، پنجره چت باز می‌شود
        """
        sel = self.listbox.curselection()
        if not sel:
            return
        entry = self.listbox.get(sel[0])
        ip = entry.replace("⭐ ", "").split(":")[0]
        self.open_chat(ip)



    def open_chat(self, ip):
        """
        باز کردن پنجره گفت‌وگو با طراحی جدید حبابی شبیه تلگرام
        """
        if ip in self.chat_windows:
            self.new_msg_peers.discard(ip)
            self.refresh_peers()
            return

        port = self.peers[ip]["port"]

        # پنجره اصلی چت
        win = tk.Toplevel(self.root)
        win.title(f"💬 Chat with {ip}")
        win.configure(bg="#f0f2f7")

        # بعد از ساخت اولیه پنجره، 100ms تأخیر بده تا ابعاد واقعی مشخص بشن
        win.update_idletasks()
        center_window(win, 450, 550, self.root)



        # نوار بالای چت
        header = tk.Frame(win, bg="#5b9bd5", height=50)
        header.pack(fill="x")
        tk.Label(header, text=f"Chat with {ip}", bg="#5b9bd5", fg="white",
                 font=("Segoe UI", 12, "bold")).pack(side="left", padx=10, pady=10)

        # بخش پیام‌ها
        chat_frame = tk.Frame(win, bg="#e7eefb")
        chat_frame.pack(fill="both", expand=True)

        canvas = tk.Canvas(chat_frame, bg="#e7eefb", highlightthickness=0)
        scrollbar = tk.Scrollbar(chat_frame, command=canvas.yview)
        scroll_frame = tk.Frame(canvas, bg="#e7eefb")

        scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # تابع ساخت حباب پیام
        def add_bubble(sender, msg, t=None):
            frame = tk.Frame(scroll_frame, bg="#e7eefb")
            anchor = "e" if sender == "me" else "w"
            color = "#d0e7ff" if sender == "me" else "white"

            bubble = tk.Label(
                frame, text=msg, bg=color, fg="black",
                font=("Segoe UI", 10), wraplength=320,
                padx=10, pady=6, justify="left",
                relief="ridge", bd=1
            )
            bubble.pack(anchor=anchor, padx=10, pady=3)

            if t:
                tk.Label(frame, text=t, bg="#e7eefb", fg="#777",
                         font=("Segoe UI", 8)).pack(anchor=anchor)
            frame.pack(fill="x", pady=3)

            canvas.update_idletasks()
            canvas.yview_moveto(1)
            return win


        # نمایش تاریخچه قبلی
        with history_lock:
            for msg in history.get(ip, []):
                if msg.get("type") != "msg":
                    continue
                sender = "me" if msg["dir"] == "out" else "you"
                add_bubble(sender, msg["msg"], msg["time"])

        # نوار پایین
        bottom = tk.Frame(win, bg="#f0f2f7")
        bottom.pack(fill="x", padx=10, pady=8)

        entry = tk.Entry(bottom, font=("Segoe UI", 10), width=55, relief="flat", bd=2)
        entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        def send_msg():
            msg = entry.get().strip()
            if not msg:
                return
            entry.delete(0, tk.END)
            ok = self.send_message(ip, port, msg)
            if ok:
                add_bubble("me", msg, now())
                record_history(ip, "out", msg, entry_type="msg")
            else:
                add_bubble("system", "[Send failed]")

        send_btn = tk.Button(bottom, text="✈️", bg="#5b9bd5", fg="white",
                             font=("Segoe UI", 11, "bold"), relief="flat",
                             width=4, command=send_msg)
        send_btn.pack(side="right")

        self.chat_windows[ip] = (win, scroll_frame)
        win.chat_area = scroll_frame


        def on_close():
            if ip in self.chat_windows:
                del self.chat_windows[ip]
            self.new_msg_peers.discard(ip)
            self.refresh_peers()
            win.destroy()

        win.protocol("WM_DELETE_WINDOW", on_close)

    # ----------------- راه‌اندازی Listener (برای دریافت پیام‌های ورودی) -----------------

    def start_listener(self):
        """
        انتخاب پورت برای این دستگاه و راه‌اندازی listener.
        اگر پورت قبلی مشغول باشد یا bind نشود، پورت جدیدی می‌گیرد.
        خطاها را در UI و لاگ نمایش می‌دهد.
        """
        try:
            # تلاش برای خواندن پورت قبلی از فایل
            if os.path.exists(PORT_FILE):
                try:
                    port = int(open(PORT_FILE).read().strip())
                    logger.info("Read saved port: %d", port)
                except Exception:
                    logger.warning("Failed to read saved port file, using random port")
                    port = 0
            else:
                port = 0

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # تلاش برای bind روی پورت ذخیره‌شده
            bound = False
            if port != 0:
                try:
                    s.bind(("", port))
                    bound = True
                    logger.info("Successfully bound to saved port %d", port)
                except OSError as e:
                    logger.warning("Saved port %d was busy or unavailable: %s", port, e)

            # در صورت عدم موفقیت، پورت تصادفی انتخاب می‌شود
            if not bound:
                s.bind(("", 0))
                port = s.getsockname()[1]
                with open(PORT_FILE, "w") as f:
                    f.write(str(port))
                logger.info("Selected new random port %d and saved to %s", port, PORT_FILE)

            # قرار دادن سوکت در حالت شنود
            s.listen(5)

            # راه‌اندازی نخ گوش‌دهنده
            threading.Thread(target=self.listen_thread, args=(s,), daemon=True).start()

            # اطلاع در رابط کاربری
            logger.info("Listening on port %d", port)
            # messagebox.showinfo("Listening", f"✅ Listening on port {port}")
            return port

        except OSError as e:
            logger.exception("Failed to bind or listen on port")
            messagebox.showerror(
                "Error",
                f"❌ Cannot start listener on port {port if 'port' in locals() else '?'}\n\n{e}"
            )
            return None
        except Exception as e:
            logger.exception("Unexpected error in start_listener")
            messagebox.showerror("Error", f"Unexpected error while starting listener:\n\n{e}")
            return None

    def test_connection(self):
        """
        تست دستی اتصال به یک IP:Port، با نمایش دلیل دقیق در صورت خطا.
        """
        txt = simpledialog.askstring("Test Connection", "Enter IP:Port to test:")
        if not txt:
            return

        try:
            ip, port = txt.split(":")
            port = int(port)
        except Exception:
            messagebox.showerror("Error", "Invalid format. Use like: 192.168.2.52:5050")
            return

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)

        try:
            start = time.time()
            s.connect((ip, port))
            elapsed = int((time.time() - start) * 1000)
            messagebox.showinfo("Success", f"✅ Connected to {ip}:{port}\nRTT: {elapsed} ms")
            s.close()
            return

        except socket.timeout:
            reason = "⏱️ Connection timed out\n\n➡ احتمالاً مسیر شبکه یا فایروال ارتباط را مسدود کرده است."
        except ConnectionRefusedError:
            reason = "🔴 Connection refused\n\n➡ پورت بسته است یا برنامه در سیستم مقصد در حال اجرا نیست."
        except OSError as e:
            if "No route" in str(e):
                reason = "⚠️ Host unreachable\n\n➡ مسیر بین subnet‌ها وجود ندارد یا gateway درست تنظیم نشده است."
            elif "Network is unreachable" in str(e):
                reason = "🌐 Network unreachable\n\n➡ کارت شبکه یا آدرس IP اشتباه است."
            elif "Name or service not known" in str(e):
                reason = "⚠️ Invalid IP address or hostname"
            else:
                reason = f"⚠️ Unexpected error:\n{e}"
        except Exception as e:
            reason = f"⚠️ Unknown error:\n{e}"
        finally:
            s.close()

        messagebox.showerror("Failed", f"❌ Connection to {ip}:{port} failed.\n\n{reason}")


    def listen_thread(self, sock):
        while True:
            try:
                conn, addr = sock.accept()
                threading.Thread(
                    target=self.handle_conn, args=(conn, addr), daemon=True
                ).start()
            except OSError as e:
                logger.warning("Socket closed or invalid: %s", e)
                break
            except Exception:
                logger.exception("Error in listen_thread")
    def handle_conn(self, conn, addr):
        """
        مدیریت اتصال ورودی:
        - دریافت و رمزگشایی پیام
        - تشخیص نوع پیام (PING / PONG / MSG)
        - ذخیره‌ی نام فرستنده (اگر موجود باشد)
        """
        ip = addr[0]
        try:
            data = conn.recv(8192)
            if not data:
                conn.close()
                return

            # --- رمزگشایی پیام ---
            try:
                obj = unpack_payload(data)
                logger.debug("handle_conn from %s (source_port=%s): %s", addr[0], addr[1], obj)
            except Exception as e:
                logger.warning("Failed to unpack payload from %s: %s", ip, e)
                conn.close()
                return

            # --- ذخیره نام فرستنده اگر موجود است ---
            try:
                if isinstance(obj, dict):
                    peer_name = obj.get("name")
                    if peer_name:
                        p = self.peers.setdefault(ip, {})

                        # فقط اگر پورت هنوز ذخیره نشده، از پورت فعلی استفاده کن
                        if "port" not in p or not p.get("port"):
                            p["port"] = addr[1]

                        # در غیر این صورت، مقدار فعلی پورت را نگه دار (تغییر نده)
                        p["name"] = peer_name
                        p["online"] = True
                        p["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        save_peers(self.peers)
                        try:
                            self.root.after(0, self.refresh_peers)
                        except Exception:
                            pass
            except Exception:
                logger.exception("Failed to store peer name from incoming payload")

            # --- 1. PING ---
            if isinstance(obj, dict) and "ping" in obj:
                resp = {"pong": 1, "rtt_ms": 0}
                try:
                    conn.send(pack_payload(resp))
                    p = self.peers.setdefault(ip, {})
                    # دیگر پورت را از addr[1] نگیریم (چون موقتی است)
                    if "port" not in p or not p.get("port"):
                        p["port"] = addr[1]
                    p["online"] = True
                    p["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    save_peers(self.peers)
                except Exception:
                    logger.debug("Failed to send PONG to %s", ip)

            # --- 2. PONG ---
            elif isinstance(obj, dict) and "pong" in obj:
                p = self.peers.setdefault(ip, {})
                # پورت را فقط در صورت نداشتن مقدار ثبت کن
                if "port" not in p or not p.get("port"):
                    p["port"] = addr[1]
                p["online"] = True
                p["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                save_peers(self.peers)
                logger.debug("Received PONG from %s", ip)

            # --- 3. MSG ---
            elif isinstance(obj, dict) and "msg" in obj:
                msg = obj["msg"]
                sender_port = None
                if "from_port" in obj:
                    try:
                        sender_port = int(obj["from_port"])
                    except Exception:
                        sender_port = obj.get("from_port")

                # پیام تست داخلی
                if msg == "__TEST_REPLY__":
                    if sender_port:
                        p = self.peers.setdefault(ip, {})
                        # فقط اگر پورت ثبت نشده، مقدار جدید بده
                        if "port" not in p or not p.get("port"):
                            p["port"] = sender_port
                        p["online"] = True
                        save_peers(self.peers)
                    try:
                        self.root.after(0, self.refresh_peers)
                    except Exception:
                        logger.debug("Failed to refresh peers after TEST_REPLY")
                    return

                # پیام واقعی
                try:
                    record_history(ip, "in", msg, entry_type="msg")
                except Exception:
                    logger.warning("Failed to record incoming msg from %s", ip)

                logger.info("Received message from %s", ip)

                if sender_port:
                    p = self.peers.setdefault(ip, {})
                    # فقط اگر پورت قبلاً تنظیم نشده بود، مقدار جدید بده
                    if "port" not in p or not p.get("port"):
                        p["port"] = sender_port
                    p["online"] = True
                    save_peers(self.peers)

                try:
                    self.root.after(0, self.refresh_peers)
                    self.root.after(0, lambda ip=ip, msg=msg: self.display_incoming(ip, msg))
                except Exception:
                    logger.warning("Failed to update UI after message from %s", ip)

            # --- 4. Unknown ---
            else:
                logger.debug("Unknown object from %s: %s", ip, obj)

        except Exception as e:
            logger.warning("handle_conn error for %s: %s", ip, e)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def display_incoming(self, ip, msg):
        """
        این تابع پیام‌های ورودی را در رابط کاربری نشان می‌دهد.
        اگر پنجره چت برای آن IP باز نباشد، آیکون پیام جدید (⭐) فعال می‌شود.
        """
        # اگر همتا در لیست peers وجود نداشت، به عنوان آنلاین اضافه می‌شود
        if ip not in self.peers:
            self.peers[ip] = {"port": 0, "online": True}

        # اگر پنجره چت باز نباشد → نوتیف پیام جدید نمایش داده شود
        if ip not in self.chat_windows:
            self.new_msg_peers.add(ip)
            self.refresh_peers()
            self.play_notify_sound()
            return  # چون پنجره باز نیست

        # اگر پنجره باز است → ستاره پیام جدید حذف می‌شود
        self.new_msg_peers.discard(ip)
        self.refresh_peers()

        # گرفتن پنجره و ناحیه‌ی چت مربوط به IP
        win, chat_area = self.chat_windows.get(ip, (None, None))
        if not win or not chat_area:
            self.new_msg_peers.add(ip)
            self.refresh_peers()
            self.play_notify_sound()
            return

        # ساخت حباب پیام دریافتی در سمت چپ (مثل تلگرام)
        frame = tk.Frame(chat_area, bg="#e7eefb")
        frame.pack(fill="x", pady=3, anchor="w")

        bubble = tk.Label(
            frame,
            text=msg,
            bg="white",
            fg="black",
            font=("Segoe UI", 10),
            wraplength=320,
            justify="left",
            padx=10,
            pady=6,
            relief="ridge",
            bd=1
        )
        bubble.pack(anchor="w", padx=10, pady=2)

        tk.Label(
            frame,
            text=now(),
            bg="#e7eefb",
            fg="#777",
            font=("Segoe UI", 8)
        ).pack(anchor="w", padx=15)

        # اسکرول خودکار به پایین
        chat_area.update_idletasks()
        chat_area.master.yview_moveto(1)

        # پخش صدای اعلان (اختیاری)
        self.play_notify_sound()


    def append_to_chat_window(self, ip, who, msg_text):
        """
        این تابع یک پیام را در پنجره چت مخصوص IP مشخص نمایش می‌دهد.
        - ip: آدرس همتا (Peer)
        - who: فرستنده پیام ("You" یا IP طرف مقابل)
        - msg_text: متن پیام
        """
        # گرفتن ویجت text مربوط به پنجره چت
        win_text = self.chat_windows.get(ip, (None, None))[1]
        if not win_text:
            # اگر پنجره باز نبود، هیچ کاری نمی‌کند
            return

        # تغییر وضعیت text به قابل ویرایش
        win_text.config(state='normal')
        # درج پیام جدید با timestamp
        win_text.insert('end', f"[{now()}] {who}: {msg_text}\n")
        # دوباره غیرقابل ویرایش کردن text
        win_text.config(state='disabled')
        # اسکرول خودکار به آخرین پیام
        win_text.see('end')


    def play_notify_sound(self):
        """
        یک صدای ساده هشدار برای پیام جدید پخش می‌کند.
        روی Windows از winsound استفاده می‌کند و روی سیستم‌های دیگر از بوق terminal.
        """
        if platform.system() == "Windows":
            winsound.MessageBeep(winsound.MB_ICONASTERISK)
        else:
            os.system('echo -n "\\a"')  # basic beep


    def send_message(self, ip, port, msg):
        """
        ارسال پیام به همتا (peer) با کنترل کامل خطا و ثبت لاگ دقیق.
        """
        try:
            # اطمینان از عدد بودن پورت
            try:
                port = int(port)
            except Exception:
                logger.warning("send_message: port is not int for %s: %r", ip, port)

            # ساخت سوکت و اتصال
            logger.debug(
                "send_message -> connecting to %s:%s (from listen port %s), msg=%s",
                ip, port, self.listen_port,
                msg if len(msg) < 100 else msg[:100] + "..."
            )
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((ip, port))

            # ---- آماده‌سازی پیام ----
            try:
                name_val = ""
                if hasattr(self, "entry_name"):
                    name_val = self.entry_name.get().strip()
                elif hasattr(self, "my_name"):
                    name_val = self.my_name
            except Exception:
                name_val = ""

            payload = {"msg": msg, "from_port": self.listen_port}

            # اطمینان از اینکه نام قابل رمزگذاری است (UTF-8 safe)
            if name_val:
                safe_name = name_val.encode("utf-8", "ignore").decode("utf-8", "ignore")
                payload["name"] = safe_name

            # ارسال داده بسته‌بندی‌شده
            packed = pack_payload(payload)
            s.send(packed)

            # بستن امن سوکت
            try:
                s.shutdown(socket.SHUT_WR)
            except Exception:
                pass
            s.close()

            logger.debug("send_message -> sent successfully to %s:%s", ip, port)
            return True

        except Exception as e:
            logger.exception(f"send_message failed to {ip}:{port} ({e})")
            return False


    def check_peers_online(self):
        """
        یک حلقه دائمی برای بررسی وضعیت آنلاین بودن همتاها.
        هر چند ثانیه (CHECK_INTERVAL) همه‌ی IPها ping می‌شوند.
        """
        while True:
            for ip, info in list(self.peers.items()):
                last_seen = info.get("last_seen")
                if last_seen:
                    try:
                        t = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
                        if (datetime.now() - t).seconds > 60:
                            continue  # بیشتر از ۱ دقیقه از آخرین تماس گذشته، فعلاً پینگ نکن
                    except:
                        pass
                port = info.get("port")
                if not port:
                    continue  # اگر port تعریف نشده، برو سراغ بعدی
                ok = self.ping_peer(ip, port)

                info["online"] = ok
                self.root.after(0, self.refresh_peers)


            # بعد از بررسی همه همتاها، UI لیست کاربران را رفرش می‌کند
            self.refresh_peers()

            # تاخیر بین چک‌ها
            time.sleep(CHECK_INTERVAL)


    def ping_peer(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            start = time.time()
            s.connect((ip, port))
            s.send(pack_payload({"ping": 1}))
            try:
                s.shutdown(socket.SHUT_WR)
            except Exception:
                pass
            data = s.recv(8192)
            s.close()

            obj = unpack_payload(data) if data else {}
            elapsed_ms = int((time.time() - start) * 1000)

            if isinstance(obj, dict) and obj.get("pong"):
                if ip in self.peers:
                    self.peers[ip]["online"] = True
                    self.peers[ip]["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    save_peers(self.peers)
                return True

        except Exception as e:
            logger.warning("ping_peer failed for %s:%s (%s)", ip, port, e)
            if ip in self.peers:
                self.peers[ip]["online"] = False
                save_peers(self.peers)
            return False



    # ----------------- History management UI functions --------------------

    def prompt_keep_last_n(self):
        """
        نمایش یک پنجره ورودی برای گرفتن عدد N از کاربر.
        هدف: نگه داشتن فقط N پیام آخر برای هر همتا.
        """
        ans = simpledialog.askinteger(
            "Keep last N",
            "Keep last N messages per peer (N):",
            minvalue=1,
            initialvalue=100
        )
        if ans is None:
            return  # اگر کاربر انصراف داد، هیچ کاری انجام نمی‌شود
        self.keep_last_n(ans)


    def prompt_keep_last_days(self):
        """
        نمایش پنجره ورودی برای گرفتن تعداد روزها (X).
        هدف: نگه داشتن فقط پیام‌های X روز اخیر برای هر همتا.
        """
        ans = simpledialog.askinteger(
            "Keep last X days",
            "Keep messages from last X days (per peer):",
            minvalue=1,
            initialvalue=30
        )
        if ans is None:
            return
        self.keep_last_days(ans)


    def clear_history(self):
        """
        حذف کامل تاریخچه پیام‌ها برای همه‌ی همتاها.
        قبل از حذف، از کاربر تایید گرفته می‌شود.
        """
        if messagebox.askyesno("Clear History", "Are you sure? This will delete all stored history."):
            try:
                with history_lock:  # قفل‌گذاری برای جلوگیری از دسترسی همزمان
                    history.clear()  # پاک کردن کل تاریخچه از حافظه
                    save_history(history)  # ذخیره تغییرات در فایل
                messagebox.showinfo("Done", "History cleared.")
                logger.info("User cleared all history")
            except Exception:
                logger.exception("Failed to clear history")
                messagebox.showerror("Error", "Failed to clear history. Check logs.")


    def keep_last_n(self, n):
        """
        فقط N پیام آخر (پیام + پینگ) را برای هر همتا نگه می‌دارد.
        در صورت زیاد بودن، بقیه پیام‌ها حذف می‌شوند.
        """
        try:
            with history_lock:
                for peer, lst in list(history.items()):
                    if len(lst) > n:
                        # فقط N پیام آخر نگه داشته می‌شود
                        history[peer] = lst[-n:]
                save_history(history)
            messagebox.showinfo("Done", f"Kept last {n} messages per peer.")
            logger.info("Compressed history to last %d per peer", n)
        except Exception:
            logger.exception("keep_last_n failed")
            messagebox.showerror("Error", "Failed to compress history. Check logs.")


    def keep_last_days(self, days):
        """
        فقط پیام‌های X روز اخیر را برای هر همتا نگه می‌دارد.
        پیام‌های قدیمی‌تر از cutoff حذف می‌شوند.
        """
        try:
            cutoff = datetime.now() - timedelta(days=days)
            with history_lock:
                for peer, lst in list(history.items()):
                    new_lst = []
                    for entry in lst:
                        try:
                            # تبدیل زمان پیام به آبجکت datetime
                            t = datetime.strptime(entry.get("time"), "%Y-%m-%d %H:%M:%S")
                        except Exception:
                            # پیام‌هایی که زمان معتبری ندارند، حذف می‌شوند
                            continue
                        if t >= cutoff:
                            new_lst.append(entry)
                    history[peer] = new_lst
                save_history(history)

            messagebox.showinfo("Done", f"Kept messages from last {days} days.")
            logger.info("Compressed history to last %d days", days)

        except Exception:
            logger.exception("keep_last_days failed")
            messagebox.showerror("Error", "Failed to compress history. Check logs.")


    def prompt_set_shared_key(self):
        """
        نمایش یک دیالوگ برای تنظیم یا حذف کلید رمز مشترک (Shared Key).
        اگر کلید تعیین شود، ارتباطات رمزگذاری XOR+HMAC می‌شوند.
        اگر خالی باشد، ارتباطات به صورت متن ساده JSON رد و بدل می‌شود.
        """
        global SHARED_KEY
        cur = SHARED_KEY or "<not set>"  # نمایش وضعیت فعلی کلید

        ans = simpledialog.askstring(
            "Shared Key",
            f"Current key: {cur}\nEnter new shared key (empty to disable):"
        )
        if ans is None:
            return  # اگر کاربر انصراف داد، کاری انجام نمی‌شود

        SHARED_KEY = ans.strip()
        if SHARED_KEY:
            logger.warning("Shared key enabled - using simple XOR+HMAC (NOT TLS).")
            messagebox.showinfo(
                "Shared Key",
                "Shared key set. Note: This uses a simple XOR+HMAC scheme (not TLS)."
            )
        else:
            logger.info("Shared key disabled by user.")
            messagebox.showinfo(
                "Shared Key",
                "Shared key disabled. Communications will be plain JSON."
            )


# ----------------- Main -----------------
if __name__ == "__main__":
    """
    نقطه شروع برنامه.
    - لاگ گرفتن از وضعیت Shared Key
    - ساخت رابط کاربری Tkinter
    - ساخت نمونه‌ای از کلاس ChatApp
    - اجرای حلقه اصلی رابط کاربری
    """
    logger.info(
        "Starting p2p chat app. SHARED_KEY set: %s",
        "yes" if SHARED_KEY else "no"
    )
    root = tk.Tk()
    app = ChatApp(root)
    root.mainloop()
    

