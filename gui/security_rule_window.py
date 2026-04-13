import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

class SecurityRuleWindow:
    def __init__(self, root, server):
        self.server = server
        self.window = tk.Toplevel(root)
        self.window.title("安全规则与违规行为检测")
        self.window.geometry("550x400+300+200")
        
        self.window.transient(root)
        self.window.lift()
        self.window.focus_force()

        # ================== 新增：全局滚动容器设置 ==================
        # 1. 创建最外层容器
        container = tk.Frame(self.window)
        container.pack(fill=tk.BOTH, expand=True)

        # 2. 创建 Canvas 和 Scrollbar
        self.canvas = tk.Canvas(container, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.canvas.yview)
        
        # 3. 创建真正承载内容的 frame（放在 Canvas 内部）
        scroll_frame = tk.Frame(self.canvas)

        # 4. 配置 Canvas 联动
        scroll_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        self.canvas.create_window((0, 0), window=scroll_frame, anchor="nw", tags="frame")
        self.canvas.configure(yscrollcommand=scrollbar.set)

        # 确保内部框架宽度与 canvas 一致
        self.canvas.bind(
            "<Configure>",
            lambda e: self.canvas.itemconfig("frame", width=e.width)
        )

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 绑定鼠标滚轮事件 (兼容 Windows, MacOS 和 Linux)
        def _on_mousewheel(event):
            if event.num == 4 or event.delta > 0:
                self.canvas.yview_scroll(-1, "units")
            elif event.num == 5 or event.delta < 0:
                self.canvas.yview_scroll(1, "units")
                
        # 当鼠标进入/离开画布区域时绑定/解绑滚轮，防止影响其他窗口
        self.canvas.bind('<Enter>', lambda e: self.window.bind_all("<MouseWheel>", _on_mousewheel) or self.window.bind_all("<Button-4>", _on_mousewheel) or self.window.bind_all("<Button-5>", _on_mousewheel))
        self.canvas.bind('<Leave>', lambda e: self.window.unbind_all("<MouseWheel>") or self.window.unbind_all("<Button-4>") or self.window.unbind_all("<Button-5>"))
        # ================== 全局滚动容器设置结束 ==================

        # === 以下为你原来的代码，完全没有改动，只是把 main_frame 的父组件改成了 scroll_frame ===
        main_frame = tk.Frame(scroll_frame)
        main_frame.pack(padx=20, pady=15, fill=tk.BOTH, expand=True)

        # 1. 说明区域
        info = ("【自定义安全规则检测】\n"
                "定义目标 IP 以及一个管控的 IP 范围段。\n"
                "• 黑名单(禁止)：目标 IP 如果与范围内的 IP 通信，则视为违规。\n"
                "• 白名单(仅允许)：目标 IP 只能与范围内的 IP 通信，与其他 IP 通信视为违规。")
        tk.Label(main_frame, text=info, fg="#333333", justify=tk.LEFT).pack(anchor='w', pady=(0, 15))

        # 2. 输入区域
        input_frame = tk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=5)

        tk.Label(input_frame, text="目标 IP (IP1):").grid(row=0, column=0, sticky='w', pady=5)
        self.ip1_entry = tk.Entry(input_frame, width=20)
        self.ip1_entry.grid(row=0, column=1, padx=5)

        tk.Label(input_frame, text="管控范围起始 IP (IP2):").grid(row=1, column=0, sticky='w', pady=5)
        self.ip2_entry = tk.Entry(input_frame, width=20)
        self.ip2_entry.grid(row=1, column=1, padx=5)

        tk.Label(input_frame, text="管控范围结束 IP (IP3):").grid(row=2, column=0, sticky='w', pady=5)
        self.ip3_entry = tk.Entry(input_frame, width=20)
        self.ip3_entry.grid(row=2, column=1, padx=5)

        tk.Label(input_frame, text="规则动作:").grid(row=3, column=0, sticky='w', pady=5)
        self.rule_combo = ttk.Combobox(input_frame, values=["黑名单 (禁止访问范围)", "白名单 (仅允许访问范围)"], state="readonly", width=22)
        self.rule_combo.grid(row=3, column=1, padx=5)
        self.rule_combo.set("黑名单 (禁止访问范围)")

        self.btn_check = tk.Button(input_frame, text="执行规则检测", command=self.run_check)
        '''bg="#FFE4E1"'''
        self.btn_check.grid(row=3, column=2, padx=20)

        # 3. 结果显示区域
        tk.Label(main_frame, text="违规连接列表:").pack(anchor='w', pady=(15, 5))
        self.result_text = scrolledtext.ScrolledText(main_frame, width=70, height=15, bg="#FDFDFD")
        self.result_text.pack(fill=tk.BOTH, expand=True)

    def run_check(self):
        ip1 = self.ip1_entry.get().strip()
        ip2 = self.ip2_entry.get().strip()
        ip3 = self.ip3_entry.get().strip()
        action_str = self.rule_combo.get()
        action_code = 0 if "黑名单" in action_str else 1 # 0: Deny, 1: Allow

        if not ip1 or not ip2 or not ip3:
            messagebox.showwarning("提示", "请完整填写三个 IP 地址！", parent=self.window)
            return

        self.btn_check.config(state=tk.DISABLED, text="检测中...")
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"正在全局扫描 {ip1} 的违规行为...\n\n")
        self.window.update()

        request = {
            "command": "CHECK_SECURITY",
            "payload": {
                "ip1": ip1, "ip2": ip2, "ip3": ip3, "action": action_code
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
            self.result_text.delete(1.0, tk.END)
            for item in data:
                self.result_text.insert(tk.END, item+'\n')
        except Exception as e:
            messagebox.showerror("网络错误", f"无法连接后台:\n{e}", parent=self.window)
        finally:
            try:
                self.cut_daemon_connection()
            except:
                pass
            self.btn_check.config(state=tk.NORMAL, text="执行规则检测")