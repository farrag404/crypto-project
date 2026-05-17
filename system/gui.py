import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading, queue, sys, os

# ── make sure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from system.ca     import CertificateAuthority
from system.server import Server
from system.client import Client

#  COLOURS

BG    = "#1e1e1e"
BG2   = "#252525"
BG3   = "#2d2d2d"
GREEN = "#4ec9b0"
YELL  = "#dcdcaa"
RED   = "#f44747"
GRAY  = "#858585"
WHITE = "#d4d4d4"
FONT  = ("Courier New", 11)
FONTS = ("Courier New", 10)

#  LOG INTERCEPTOR
#  Capture all print() output from the real
#  modules and send it to our GUI log box.

class LogQueue:
    def __init__(self, q: queue.Queue):
        self._q = q
        self._orig = sys.stdout

    def write(self, text):
        self._orig.write(text)        # still prints to terminal
        if text.strip():
            self._q.put(text.rstrip())

    def flush(self):
        self._orig.flush()


#  APP

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Messaging System")
        self.configure(bg=BG)
        self.geometry("860x600")
        self.resizable(True, True)

        # queue for log lines coming from real modules
        self._log_q = queue.Queue()
        sys.stdout  = LogQueue(self._log_q)

        self.current = "abdelrahman"
        self.messages = []          # {from, plain, hill, stored, t}

        self._build_ui()
        self._init_system()
        self._poll_log()            # start polling the queue

    #  INIT REAL SYSTEM
   
    def _init_system(self):
        try:
            self.ca     = CertificateAuthority()
            self.server = Server(self.ca)
            self.abdelrahman  = Client("abdelrahman", self.ca)
            self.ahmed    = Client("ahmed",   self.ca)

            self.abdelrahman.connect(self.server)
            self.ahmed.connect(self.server)

            self._chat_sys("✓ System ready — abdelrahman & ahmed connected to server")
        except Exception as e:
            self._chat_sys(f"✗ Init error: {e}")

    # ─────────────────────────────────────────
    #  BUILD UI
    # ─────────────────────────────────────────
    def _build_ui(self):
        # ── Sidebar ──────────────────────────
        left = tk.Frame(self, bg=BG2, width=170)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)

        tk.Label(left, text="USERS", fg=GRAY, bg=BG2,
                 font=FONTS).pack(anchor="w", padx=10, pady=(12,4))

        self.ulbls = {}
        for user in ("abdelrahman", "ahmed"):
            lbl = tk.Label(left, text=f"  ● {user}", fg=WHITE, bg=BG2,
                           font=FONT, anchor="w", cursor="hand2")
            lbl.pack(fill="x", pady=3, padx=4)
            lbl.bind("<Button-1>", lambda e, u=user: self._select(u))
            self.ulbls[user] = lbl

        tk.Frame(left, bg=BG3, height=1).pack(fill="x", pady=8)
        tk.Label(left, text="ACTIONS", fg=GRAY, bg=BG2,
                 font=FONTS).pack(anchor="w", padx=10, pady=(0,4))

        for txt, cmd in [
            ("↻ Rotate Key",   self._rotate_key),
            ("✕ Revoke Cert",  self._revoke),
            ("⬡ Rotate CA",    self._rotate_ca),
            ("📋 Show Certs",  self._show_certs),
            ("📥 Server Inbox", self._show_inbox),
        ]:
            tk.Button(left, text=txt, fg=WHITE, bg=BG3, font=FONTS,
                      relief="flat", anchor="w", padx=8, pady=5,
                      cursor="hand2", command=cmd,
                      activebackground=BG, activeforeground=GREEN
                      ).pack(fill="x", padx=8, pady=2)

        # ── Right area ───────────────────────
        right = tk.Frame(self, bg=BG)
        right.pack(side="right", fill="both", expand=True)

        # header
        self.hdr = tk.Label(right, text="abdelrahman → server",
                            fg=GREEN, bg=BG2,
                            font=("Courier New", 12, "bold"),
                            anchor="w", padx=12, pady=7)
        self.hdr.pack(fill="x")

        # chat box
        self.chat = scrolledtext.ScrolledText(
            right, bg=BG, fg=WHITE, font=FONT,
            relief="flat", state="disabled", wrap="word", height=13)
        self.chat.pack(fill="both", expand=True, padx=4, pady=(4,0))
        self.chat.tag_config("me",  foreground=GREEN)
        self.chat.tag_config("ot",  foreground=YELL)
        self.chat.tag_config("enc", foreground=GRAY)
        self.chat.tag_config("sys", foreground=GRAY)
        self.chat.tag_config("err", foreground=RED)

        # separator + log label
        tk.Frame(right, bg=BG3, height=1).pack(fill="x", pady=(5,0))
        tk.Label(right, text="CRYPTO LOG  (real module output)",
                 fg=GRAY, bg=BG, font=FONTS, anchor="w", padx=6).pack(fill="x")

        # log box
        self.log_box = scrolledtext.ScrolledText(
            right, bg=BG, fg=GRAY, font=FONTS,
            relief="flat", state="disabled", wrap="word", height=8)
        self.log_box.pack(fill="both", padx=4, pady=(0,4))
        self.log_box.tag_config("ca",     foreground=YELL)
        self.log_box.tag_config("server", foreground="#9cdcfe")
        self.log_box.tag_config("client", foreground=GREEN)
        self.log_box.tag_config("err",    foreground=RED)

        # input row
        row = tk.Frame(right, bg=BG2)
        row.pack(fill="x")
        self.entry = tk.Entry(row, bg=BG3, fg=WHITE, font=FONT,
                              insertbackground=GREEN, relief="flat", bd=6)
        self.entry.pack(side="left", fill="x", expand=True,
                        padx=(6,4), pady=6)
        self.entry.bind("<Return>", lambda e: self._send())
        self.entry.focus()

        tk.Button(row, text="Send →", fg=BG, bg=GREEN, font=FONT,
                  relief="flat", padx=10, cursor="hand2",
                  command=self._send,
                  activebackground=WHITE
                  ).pack(side="right", padx=(0,6), pady=6)

        self._select("abdelrahman")

    # ─────────────────────────────────────────
    #  USER SELECTION
    # ─────────────────────────────────────────
    def _select(self, user):
        self.current = user
        self.hdr.config(text=f"{user} → server")
        for u, lbl in self.ulbls.items():
            lbl.config(fg=GREEN if u == user else WHITE)
        self._refresh_chat()

    # ─────────────────────────────────────────
    #  SEND MESSAGE  (uses real Client.send)
    # ─────────────────────────────────────────
    def _send(self):
        txt = self.entry.get().strip()
        if not txt:
            return
        self.entry.delete(0, "end")

        user   = self.current
        client = self.abdelrahman if user == "abdelrahman" else self.ahmed

        import time
        from symmetric.hill     import hill_encrypt
        from symmetric.vigenere import vigenere_encrypt

        HILL_KEY = [[3, 3], [2, 5]]
        hill   = hill_encrypt(txt, HILL_KEY)
        stored = vigenere_encrypt(txt, "SECUREMSG")
        t      = time.strftime("%H:%M:%S")

        # call the real client.send() — output goes to log via interceptor
        try:
            client.send(txt)
            self.messages.append({
                "from": user, "plain": txt,
                "hill": hill, "stored": stored, "t": t
            })
        except Exception as e:
            self._chat_sys(f"✗ Send error: {e}")

        self._refresh_chat()

    # ─────────────────────────────────────────
    #  ACTIONS
    # ─────────────────────────────────────────
    def _rotate_key(self):
        user   = self.current
        client = self.abdelrahman if user == "abdelrahman" else self.ahmed
        try:
            client.rotate_session_key()
        except Exception as e:
            self._chat_sys(f"✗ Rotate error: {e}")

    def _revoke(self):
        user = self.current
        cert = self.abdelrahman.certificate if user == "abdelrahman" else self.ahmed.certificate
        try:
            self.ca.revoke_certificate(cert["serial"])
            self._chat_sys(f"✕ cert #{cert['serial']} for {user} revoked")
        except Exception as e:
            self._chat_sys(f"✗ Revoke error: {e}")

    def _rotate_ca(self):
        try:
            self.ca.rotate_keys()
            self._chat_sys("⬡ CA keys rotated — new certs issued")
        except Exception as e:
            self._chat_sys(f"✗ CA rotate error: {e}")

    def _show_certs(self):
        lines = "CERTIFICATES\n" + "─"*40 + "\n"
        for name, client in (("abdelrahman", self.abdelrahman), ("ahmed", self.ahmed)):
            cert = client.certificate
            ok, reason = self.ca.verify_certificate(cert), "?"
            valid = self.ca.verify_certificate(cert)
            status = "VALID ✓" if valid else "INVALID ✗"
            lines += f"  {name:8}  serial=#{cert['serial']}  {status}\n"
        crl = sorted(self.ca.get_crl())
        lines += f"\nCRL: {crl if crl else 'empty'}"
        messagebox.showinfo("Certificates", lines)

    def _show_inbox(self):
        # show server inbox in a popup
        lines = "SERVER INBOX\n" + "─"*40 + "\n"
        if not self.server._inbox:
            lines += "  (empty)"
        else:
            from symmetric.vigenere import vigenere_decrypt
            for i, rec in enumerate(self.server._inbox, 1):
                dec = vigenere_decrypt(rec["encrypted_storage"], "SECUREMSG")
                lines += f"\n  [{i}] {rec['timestamp']}  from={rec['from']}\n"
                lines += f"       stored : {rec['encrypted_storage']}\n"
                lines += f"       plain  : {dec}\n"
        messagebox.showinfo("Server Inbox", lines)

    # ─────────────────────────────────────────
    #  CHAT RENDERING
    # ─────────────────────────────────────────
    def _refresh_chat(self):
        self.chat.config(state="normal")
        self.chat.delete("1.0", "end")
        for m in self.messages:
            is_me = m["from"] == self.current
            tag   = "me" if is_me else "ot"
            name  = "you" if is_me else m["from"]
            self.chat.insert("end", f"{name:8}  {m['t']}\n", tag)
            self.chat.insert("end", f"          {m['plain']}\n", tag)
            self.chat.insert("end",
                f"          hill: {m['hill']}  |  rest: {m['stored']}\n\n", "enc")
        self.chat.config(state="disabled")
        self.chat.see("end")

    def _chat_sys(self, text):
        self.chat.config(state="normal")
        self.chat.insert("end", f"  {text}\n", "sys")
        self.chat.config(state="disabled")
        self.chat.see("end")

    # ─────────────────────────────────────────
    #  LOG POLLING  (reads from real modules)
    # ─────────────────────────────────────────
    def _poll_log(self):
        try:
            while True:
                line = self._log_q.get_nowait()
                self._append_log(line)
        except queue.Empty:
            pass
        self.after(100, self._poll_log)

    def _append_log(self, text):
        self.log_box.config(state="normal")
        # colour by source
        if "[CA]"     in text: tag = "ca"
        elif "[SERVER]" in text: tag = "server"
        elif "[CLIENT"  in text: tag = "client"
        elif "✗" in text or "ERROR" in text: tag = "err"
        else: tag = ""
        self.log_box.insert("end", text + "\n", tag)
        self.log_box.config(state="disabled")
        self.log_box.see("end")


# ══════════════════════════════════════════
if __name__ == "__main__":
    app = App()
    app.mainloop()
    sys.stdout = sys.__stdout__     # restore on close