import tkinter as tk
from tkinter import scrolledtext, messagebox

class StarStructureWindow:
    def __init__(self, root, server):
        self.server = server
        # 必须使用 Toplevel，依附于主窗口
        self.window = tk.Toplevel(root)
        self.window.title("星状结构检测 (异常/核心节点分析)")
        self.window.geometry("550x400+300+200")
        
        # 保证弹窗在主窗口之上
        self.window.transient(root)
        self.window.lift()
        self.window.focus_force()
        
        # 统一的边距控制
        main_frame = tk.Frame(self.window)
        main_frame.pack(padx=20, pady=15, fill=tk.BOTH, expand=True)

        # 1. 顶部提示与说明
        info_text = ("【星型结构检测】\n"
                     "定义：中心节点与 20（默认）个或以上的节点相连，且这些边缘节点只与中心节点建立连接。\n"
                     "意义：常用于识别核心服务器节点，或发现可疑的僵尸网络C&C控制节点。")
        lbl_hint = tk.Label(main_frame, text=info_text, fg="#333333", justify=tk.LEFT)
        lbl_hint.pack(anchor='w', pady=(0, 5))

        # 2. 按钮区域
        btn_frame = tk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=5)

        lbl_star = tk.Label(btn_frame, text="自定义阈值:")
        lbl_star.pack(side=tk.LEFT, pady=5, padx=(0, 5))

        self.star_entry = tk.Entry(btn_frame, width=10)
        self.star_entry.pack(side=tk.LEFT, padx=5)

        self.btn_search = tk.Button(btn_frame, text="扫描星状结构", command=self.run_detection, width=15)
        self.btn_search.pack(side=tk.LEFT, padx=15)

        # 3. 结果显示区域
        tk.Label(main_frame, text="检测结果 (中心节点 IP : 边缘节点列表):").pack(anchor='w', pady=(5, 5))
        self.result_text = scrolledtext.ScrolledText(main_frame, width=70, height=18, bg="#F8F8F8")
        self.result_text.pack(fill=tk.BOTH, expand=True)

    def run_detection(self):
        self.btn_search.config(state=tk.DISABLED, text="正在扫描全图...")
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, "正在请求 C 引擎进行图结构遍历...\n\n")
        self.window.update()
        self.star_threshold = int(self.star_entry.get().strip())

        # 封装请求，发给 Daemon
        request = {
            "command": "FIND_STAR",
            "payload": {
                "threshold": self.star_threshold
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
            if len(data) == 0:
                raise Exception(f"未找到符合阈值{self.star_threshold}的节点")
            for item in data:
                self.result_text.insert(tk.END, item+'\n')

        except Exception as e:
            messagebox.showerror("网络错误", f"无法连接后台服务:\n{e}", parent=self.window)
        finally:
            try:
                self.cut_daemon_connection()
            except:
                pass
            self.btn_search.config(state=tk.NORMAL, text="扫描星状结构")