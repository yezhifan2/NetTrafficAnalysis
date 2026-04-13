import tkinter as tk
from tkinter import scrolledtext, messagebox

class PathFindWindow:
    def __init__(self, root, server):
        self.server = server
        self.window = tk.Toplevel(root)
        self.window.title("路径查找与拥塞分析")
        self.window.geometry("550x400+300+200")
        
        # 让子窗口保持在主窗口之上
        self.window.transient(root)
        
        # 统一的边距控制
        main_frame = tk.Frame(self.window)
        main_frame.pack(padx=20, pady=(10, 20), fill=tk.BOTH, expand=True)

        # 1. 顶部提示
        lbl_hint = tk.Label(main_frame, text="请输入源 IP 和目的 IP，系统将计算跳数最少与拥塞最小的路径", fg="#555555")
        lbl_hint.pack(anchor='w', pady=5)

        # 2. 输入区域 (利用 Frame 保持同一行)
        input_frame = tk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=5)

        tk.Label(input_frame, text="源 IP:").grid(row=0, column=0, padx=(0, 5), sticky='w')
        self.src_entry = tk.Entry(input_frame, width=18)
        self.src_entry.grid(row=0, column=1, padx=5)

        tk.Label(input_frame, text="目的 IP:").grid(row=0, column=2, padx=(15, 5), sticky='w')
        self.dst_entry = tk.Entry(input_frame, width=18)
        self.dst_entry.grid(row=0, column=3, padx=5)

        self.btn_search = tk.Button(input_frame, text="开始分析", command=self.run_analysis, width=10)
        self.btn_search.grid(row=0, column=4, padx=(15, 0))

        # 3. 结果显示区域
        tk.Label(main_frame, text="分析结果:").pack(anchor='w', pady=5)
        self.result_text = scrolledtext.ScrolledText(main_frame, width=60, height=15, bg="#F8F8F8")
        self.result_text.pack(fill=tk.BOTH, expand=True)

    def run_analysis(self):
        src_ip = self.src_entry.get().strip()
        dst_ip = self.dst_entry.get().strip()

        if not src_ip or not dst_ip:
            messagebox.showwarning("提示", "请输入完整的源 IP 和目的 IP！", parent=self.window)
            return

        self.btn_search.config(state=tk.DISABLED, text="计算中...")
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"正在连接后台分析 {src_ip} -> {dst_ip} 的路径...\n\n")
        self.window.update()

        # 封装请求，发给 Daemon
        request = {
            "command": "FIND_PATH",
            "payload": {
                "src_ip": src_ip,
                "dst_ip": dst_ip
            }
        }

        try:
            if not self.server.test_daemon():
                self.server.start_daemon()
            self.server.connect_daemon()
            self.server.send_daemon(request)
            result = self.server.recv_daemon(timeout=10)
            if result.get("status") != "success":
                raise Exception(result.get("message"))
            data = result.get("data",[])
            self.result_text.delete("1.0", tk.END)
            for item in data:
                self.result_text.insert(tk.END, item+'\n')
        except Exception as e:
            messagebox.showerror("网络错误", f"无法连接后台服务:\n{e}", parent=self.window)
        finally:
            try:
                self.cut_daemon_connection()
            except:
                pass
            self.btn_search.config(state=tk.NORMAL, text="开始分析")