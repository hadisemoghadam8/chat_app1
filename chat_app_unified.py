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

# بررسی سیستم‌عامل؛ اگر ویندوز بود، ماژول winsound برای پخش صدای اعلان وارد می‌شود
if platform.system() == "Windows":
    import winsound  # For notification sound

# ------------------- Configuration -------------------
# نام فایل‌هایی که برای ذخیره داده‌ها استفاده می‌شوند
HISTORY_FILE = "chat_history.json"    # فایل ذخیره تاریخچه پیام‌ها
PORT_FILE = f"listen_port_{socket.gethostname()}.txt"       # فایل ذخیره پورت شنود
LOG_FILE = "app.log"                  # فایل لاگ برنامه

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
ch.setLevel(logging.INFO)
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

        # نگهداری لیست همتایان (peers) و پنجره‌های چت باز شده
        self.peers = {}
        self.chat_windows = {}

        # نگهداری IP هایی که پیام جدید دارند (برای ستاره‌دار کردن در لیست)
        self.new_msg_peers = set()

        # راه‌اندازی رابط کاربری
        self.ui_setup()

        # راه‌اندازی یک thread برای بررسی آنلاین بودن همتایان
        threading.Thread(target=self.check_peers_online, daemon=True).start()

    def ui_setup(self):
        """
        ساخت رابط گرافیکی اصلی با Tkinter
        شامل منوها، لیست کاربران و دکمه‌های اصلی
        """
        # ساخت منوی اصلی
        menubar = tk.Menu(self.root)

        # زیرمنوی مدیریت تاریخچه
        histmenu = tk.Menu(menubar, tearoff=0)
        histmenu.add_command(label="Keep last N messages (per peer)...", command=self.prompt_keep_last_n)
        histmenu.add_command(label="Keep last X days (per peer)...", command=self.prompt_keep_last_days)
        histmenu.add_separator()
        histmenu.add_command(label="Clear all history", command=self.clear_history)
        menubar.add_cascade(label="History", menu=histmenu)

        # زیرمنوی تنظیمات
        settmenu = tk.Menu(menubar, tearoff=0)
        settmenu.add_command(label="Set shared key (enable/disable encryption)", command=self.prompt_set_shared_key)
        menubar.add_cascade(label="Settings", menu=settmenu)

        self.root.config(menu=menubar)

        # قاب اصلی برای نمایش اطلاعات و لیست
        frame = tk.Frame(self.root)
        frame.pack(padx=10, pady=10)

        # نمایش IP و پورت کاربر
        tk.Label(frame, text=f"Your IP: {self.local_ip}:{self.listen_port}", font=("Arial", 10, "bold")).pack()

        # لیست نمایش همتایان متصل (Peers)
        self.listbox = tk.Listbox(frame, width=55, height=12)
        self.listbox.pack(pady=5)
        # باز کردن پنجره چت با دوبار کلیک
        self.listbox.bind("<Double-Button-1>", self.open_chat_window)

        # دکمه‌های پایین لیست
        btn_frame = tk.Frame(frame)
        btn_frame.pack()
        tk.Button(btn_frame, text="Manual Connect", command=self.manual_connect).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Refresh", command=self.refresh_peers).pack(side="left", padx=5)

    def refresh_peers(self):
        """
        به‌روزرسانی لیست همتایان در رابط کاربری
        (نمایش آفلاین/آنلاین و ستاره پیام جدید)
        """
        self.listbox.delete(0, tk.END)
        for ip, info in self.peers.items():
            status = "🟢" if info.get("online") else "🔴"
            label = f"{ip}:{info['port']} {status}"
            if ip in self.new_msg_peers:
                label = f"⭐ {label}"
            self.listbox.insert(tk.END, label)

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
        باز کردن پنجره گفت‌وگو با یک IP مشخص
        """
        # اگر پنجره چت قبلاً باز شده باشد فقط نوتیفیکیشن پیام جدید حذف می‌شود
        if ip in self.chat_windows:
            self.new_msg_peers.discard(ip)
            self.refresh_peers()
            return

        port = self.peers[ip]["port"]

        # ساخت پنجره جدید
        win = tk.Toplevel(self.root)
        win.title(f"Chat with {ip}")

        # جعبه نمایش پیام‌ها (غیرفعال برای ویرایش)
        text = scrolledtext.ScrolledText(win, width=70, height=22, state='disabled')
        text.pack(padx=5, pady=5)

        # نمایش تاریخچه چت قبلی با این کاربر
        with history_lock:
            for msg in history.get(ip, []):
                # فقط پیام‌هایی که نوعشون "msg" هست نمایش داده می‌شن
                if msg.get("type") != "msg":
                    continue
                who = "You" if msg["dir"] == "out" else ip
                text.config(state='normal')
                text.insert('end', f"[{msg['time']}] {who}: {msg['msg']}\n")
                text.config(state='disabled')


        # فیلد وارد کردن پیام
        entry = tk.Entry(win, width=55)
        entry.pack(side='left', padx=5, pady=5, fill='x', expand=True)

        # تابع ارسال پیام
        def send_msg():
            msg = entry.get().strip()
            if not msg:
                return
            entry.delete(0, tk.END)
            ok = self.send_message(ip, port, msg)
            text.config(state='normal')
            if ok:
                # درج پیام در چت
                text.insert('end', f"[{now()}] You: {msg}\n")
                record_history(ip, "out", msg, entry_type="msg")
                logger.info("Sent message to %s", ip)
            else:
                text.insert('end', "[system] Send failed.\n")
                logger.warning("Send to %s failed", ip)
            text.config(state='disabled')
            text.see('end')

        # دکمه ارسال
        tk.Button(win, text="Send", command=send_msg).pack(side='right', padx=5, pady=5)

        # ذخیره پنجره چت در دیکشنری
        self.chat_windows[ip] = (win, text)
        # تابعی که وقتی کاربر پنجره چت را می‌بندد اجرا می‌شود
        def on_close():
            # حذف پنجره چت از دیکشنری پنجره‌های باز
            if ip in self.chat_windows:
                del self.chat_windows[ip]
            # حذف آیکون پیام جدید برای این IP (اگر وجود داشت)
            self.new_msg_peers.discard(ip)
            # به‌روزرسانی لیست کاربران
            self.refresh_peers()
            # بستن خود پنجره
            win.destroy()

        # ثبت تابع on_close به عنوان handler برای رویداد بستن پنجره (علامت ×)
        win.protocol("WM_DELETE_WINDOW", on_close)


    # ----------------- راه‌اندازی Listener (برای دریافت پیام‌های ورودی) -----------------
    def start_listener(self):
        """
        یک پورت مخصوص برای این دستگاه انتخاب می‌کند.
        اگر پورت قبلی مشغول باشد، پورت جدیدی می‌گیرد و آن را در فایل جداگانه ذخیره می‌کند.
        """
        # تلاش برای خواندن پورت قبلی
        if os.path.exists(PORT_FILE):
            try:
                port = int(open(PORT_FILE).read().strip())
            except Exception:
                port = 0
        else:
            port = 0

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # اگر پورت قبلی در دسترس نبود، یکی جدید می‌گیریم
        bound = False
        if port != 0:
            try:
                s.bind(("", port))
                logger.info("Bound to saved port %d", port)
                bound = True
            except OSError:
                logger.warning("Saved port %d was busy, trying a new one...", port)

        if not bound:
            s.bind(("", 0))
            port = s.getsockname()[1]
            with open(PORT_FILE, "w") as f:
                f.write(str(port))
            logger.info("Selected new random port %d and saved to %s", port, PORT_FILE)

        # قرار دادن سوکت در حالت شنود
        s.listen(5)

        # راه‌اندازی نخ جداگانه برای گوش دادن به اتصالات ورودی
        threading.Thread(target=self.listen_thread, args=(s,), daemon=True).start()

        # برگرداندن پورت انتخاب شده
        return port


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
        این تابع یک اتصال ورودی را مدیریت می‌کند.
        پیام را از کلاینت می‌خواند، رمزگشایی می‌کند و نوع پیام را تشخیص می‌دهد.
        """
        ip = addr[0]
        try:
            data = conn.recv(8192)  # دریافت داده از اتصال
            if not data:
                conn.close()
                return

            # تلاش برای رمزگشایی پیام دریافتی و لاگ payload برای دیباگ
            try:
                obj = unpack_payload(data)
                logger.info("handle_conn from %s (source_port=%s) payload: %s", addr[0], addr[1], obj)
            except Exception as e:
                logger.exception("Failed to unpack payload from %s: %s", ip, e)
                conn.close()
                return

            # ----------------- 1. اگر پیام از نوع PING بود -----------------
            if isinstance(obj, dict) and "ping" in obj:
                # دریافت پینگ — فقط در تاریخچه ثبت می‌شود، هرگز در UI چت نمایش داده نشود
                logger.debug("Received PING from %s", ip)
                try:
                    record_history(ip, "in", "PING (received)", entry_type="ping")
                except Exception:
                    logger.exception("Failed to record incoming ping")
                # پاسخ با یک PONG (ارسال تنها یک بار)
                resp = {"pong": 1, "rtt_ms": 0}
                try:
                    conn.send(pack_payload(resp))
                except Exception:
                    logger.exception("Failed to send pong to %s", ip)

            # ----------------- 2. اگر پیام از نوع PONG بود -----------------
            elif isinstance(obj, dict) and "pong" in obj:
                # معمولاً کمتر اتفاق می‌افتد (زمانی که PONG مستقیماً ارسال شود)
                logger.debug("Received unsolicited PONG from %s: %s", ip, obj)
                try:
                    record_history(ip, "in", f"PONG (info: {obj.get('rtt_ms',0)} ms)", entry_type="ping")
                except Exception:
                    logger.exception("Failed to record incoming pong")

            # ----------------- 3. اگر پیام چت واقعی بود -----------------
            elif isinstance(obj, dict) and "msg" in obj:
                msg = obj["msg"]
                sender_port = None
                if "from_port" in obj:
                    try:
                        sender_port = int(obj["from_port"])
                    except Exception:
                        sender_port = obj.get("from_port")
                    # ثبت یا بروزرسانی اطلاعات peer با پورت فرستنده
                    self.peers[ip] = {"port": sender_port, "online": True}

                # ذخیره پیام دریافتی در تاریخچه
                try:
                    record_history(ip, "in", msg, entry_type="msg")
                except Exception:
                    logger.exception("Failed to record incoming msg for %s", ip)

                logger.info("Received message from %s", ip)

                # --- نمایش پیام در UI در thread اصلی و رفرش لیست peers ---
                try:
                    # رفرش لیست peers در UI
                    self.root.after(0, self.refresh_peers)
                    # نمایش پیام ورودی در UI (display_incoming مدیریت ستاره/پنجره را انجام می‌دهد)
                    self.root.after(0, lambda ip=ip, msg=msg: self.display_incoming(ip, msg))

                    # spawn a background test connection to verify we can connect back to sender
                    if sender_port:
                        try:
                            threading.Thread(
                                target=self._try_connect_back_and_send_test,
                                args=(ip, sender_port),
                                daemon=True
                            ).start()
                        except Exception:
                            logger.exception("Failed to start test-reply thread for %s:%s", ip, sender_port)

                except Exception:
                    logger.exception("Failed to update UI after receiving msg")

            # ----------------- 4. پیام ناشناخته -----------------
            else:
                logger.warning("Unknown object from %s: %s", ip, obj)

        except Exception:
            logger.exception("handle_conn error for %s", ip)
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
        else:
            # اگر پنجره باز است → ستاره پیام جدید حذف می‌شود
            self.new_msg_peers.discard(ip)
            self.refresh_peers()

        # اگر پنجره چت باز است، پیام را مستقیماً در پنجره نمایش می‌دهد
        win, text = self.chat_windows.get(ip, (None, None))
        if not win:
            return
        text.config(state='normal')
        text.insert('end', f"[{now()}] {ip}: {msg}\n")
        text.config(state='disabled')
        text.see('end')

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

#فقط برای دیباگ. بعدش حذف کن ؟؟؟؟؟؟؟؟؟؟!!!!!!!!!!!
    def _try_connect_back_and_send_test(self, ip, port):
        """
        Debug helper: attempt to connect back to (ip,port) and send a tiny test message.
        This will produce logs showing success/failure and helps diagnose one-way issues.
        """
        try:
            logger.debug("Test-Reply: attempting to connect back to %s:%s", ip, port)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((ip, port))
            payload = {"msg": "__TEST_REPLY__", "from_port": self.listen_port}
            s.send(pack_payload(payload))
            s.close()
            logger.info("Test-Reply: success connecting back to %s:%s", ip, port)
        except Exception:
            logger.exception("Test-Reply: failed to connect back to %s:%s", ip, port)



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
        این تابع پیام کاربر را به یک همتای مشخص ارسال می‌کند.
        - ip: آدرس IP مقصد
        - port: پورت مقصد
        - msg: متن پیام ارسالی
        """
        try:
            # ساخت سوکت TCP
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)  # حداکثر زمان برای برقراری ارتباط
            logger.debug("send_message -> attempting connect to %s:%s (from local listen port %s)", ip, port, self.listen_port)

            # اتصال به همتا
            s.connect((ip, port))

            # بسته‌بندی پیام در قالب دیکشنری JSON
            payload = {"msg": msg, "from_port": self.listen_port}
            s.send(pack_payload(payload))# ارسال پیام رمزگذاری/فشرده شده (در صورت تعریف pack_payload)

            s.close()
            return True  # ارسال موفق
        except Exception:
            logger.exception("send_message failed to %s:%s", ip, port)
            return False  # ارسال ناموفق


    def check_peers_online(self):
        """
        یک حلقه دائمی برای بررسی وضعیت آنلاین بودن همتاها.
        هر چند ثانیه (CHECK_INTERVAL) همه‌ی IPها ping می‌شوند.
        """
        while True:
            for ip, info in list(self.peers.items()):
                # ارسال پینگ به هر همتا
                ok = self.ping_peer(ip, info["port"])
                # وضعیت آنلاین/آفلاین را بر اساس نتیجه ذخیره می‌کند
                info["online"] = ok

            # بعد از بررسی همه همتاها، UI لیست کاربران را رفرش می‌کند
            self.refresh_peers()

            # تاخیر بین چک‌ها
            time.sleep(CHECK_INTERVAL)


    def ping_peer(self, ip, port):
        """
        ارسال پینگ {"ping":1} به همتا و انتظار برای پاسخ {"pong":1, "rtt_ms":...}.
        پینگ/پونگ هرگز در UI چت نمایش داده نمی‌شوند؛ فقط به عنوان entry_type="ping" در تاریخچه ذخیره می‌شوند.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)  # زمان مجاز برای پاسخ
            start = time.time()

            # اتصال به همتا
            s.connect((ip, port))

            # ارسال پیام پینگ
            s.send(pack_payload({"ping": 1}))

            # اطلاع دادن به سیستم مقصد که دیگر داده‌ای ارسال نمی‌شود
            try:
                s.shutdown(socket.SHUT_WR)
            except Exception:
                pass

            # دریافت پاسخ پونگ (یا خالی)
            data = b""
            try:
                data = s.recv(8192)
            except Exception:
                pass

            # بازکردن بسته پونگ دریافتی
            try:
                obj = unpack_payload(data) if data else {}
            except Exception as e:
                logger.exception("Failed to unpack pong from %s: %s", ip, e)
                s.close()
                return False

            s.close()

            # محاسبه‌ی زمان رفت و برگشت پینگ به میلی‌ثانیه
            elapsed_ms = int((time.time() - start) * 1000)

            # اگر پاسخ معتبر پونگ بود
            if isinstance(obj, dict) and obj.get("pong"):
                rtt_val = obj.get("rtt_ms", elapsed_ms)
                rec_text = f"PING -> PONG ({rtt_val} ms)"
                # فقط در تاریخچه ذخیره کن (type="ping") — هرگز در chat UI نمایش داده نشود
                try:
                    record_history(ip, "out", rec_text, entry_type="ping")
                except Exception:
                    logger.exception("Failed to record ping history for %s", ip)

                logger.debug("Ping to %s success %d ms", ip, rtt_val)
                return True
            else:
                logger.debug("Ping to %s no valid pong response: %s", ip, obj)
                return False

        except Exception:
            logger.exception("ping_peer failed for %s:%s", ip, port)
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
