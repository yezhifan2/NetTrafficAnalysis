# help_window.py
import tkinter as tk
from tkinter import scrolledtext

class HelpWindow:
    def __init__(self, root):
        self.window = tk.Toplevel(root)
        self.window.title("系统使用帮助与手册")
        self.window.geometry("650x500+350+200")
        
        # 让子窗口保持在主窗口之上
        self.window.transient(root)
        self.window.lift()
        self.window.focus_force()

        self.create_ui()

    def create_ui(self):
        main_frame = tk.Frame(self.window)
        main_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

        # 顶部标题
        lbl_title = tk.Label(main_frame, text="网络流量分析系统 - 用户手册", font=("Microsoft YaHei", 14, "bold"))
        lbl_title.pack(pady=(0, 10))

        # 文本展示区域
        self.text_area = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, font=("Microsoft YaHei", 10), bg="#F8F8F8")
        self.text_area.pack(fill=tk.BOTH, expand=True)

        # 写入帮助文档内容
        help_content = """
【 1. 基础视图说明 】
本系统提供三种核心数据视图：
• IP 节点视图：统计单个 IP 的总发送、接收流量及邻点个数。
• 会话视图：统计源 IP 到目的 IP 之间的端到端通信流量、时长与会话次数。
• 记录视图：展示底层数据包级别的详细记录，包括协议与端口信息。

【 2. 快捷搜索与排序 】
• 排序：点击表格的列名（如“总流量”、“IP地址”等）即可按照该列进行升序/降序排列。
• 查找：在左下角输入框输入 IP 或关键字，点击“查找”或回车。使用“↑”“↓”按钮在匹配项中快速跳转。

【 3. 高级筛选功能 】
• 右键快捷筛选：在表格中右键点击某一行，可以快速将其 IP 设为全局过滤条件（追踪此 IP），或选择“复制整行”数据。
• 精确筛选：点击右上角“筛选...”按钮，可精确设定源 IP、目的 IP、特定端口及所允许的协议（TCP/UDP/ICMP等）。
• 单向输出比限制：点击表头“单向输出比”可自定义筛选阈值，查找只发不收或收发比例异常的节点。

【 4. 扩展分析功能 (右下角下拉菜单) 】
• 路径查找：输入源 IP 与目的 IP，系统将利用 C 引擎计算跳数最少与拥塞最小的通信路径。
• 星状结构检测：自定义阈值（如 20），扫描网络中疑似 C&C 服务器或核心网关的星型拓扑中心节点。
• 安全规则检测：配置黑白名单规则，扫描全局数据中是否存在违规通信行为。
• 子图可视化：输入目标 IP，提取其所在的连通分量，并自动在浏览器中生成交互式网络拓扑 HTML 页面。

【 5. 常见问题 】
Q: 数据量太大，加载卡顿怎么办？
A: 建议利用“筛选”功能先缩小特定网段，或调高“单向输出比”阈值过滤无效节点。

Q: C 引擎或后台服务未响应？
A: 可以尝试关闭当前主窗口，系统会自动结束残留的后台 C 进程并释放端口。重新运行程序即可恢复。
"""
        self.text_area.insert(tk.END, help_content.strip())
        
        # 设为只读状态，防止用户修改说明书内容
        self.text_area.config(state=tk.DISABLED)

        # 底部关闭按钮
        btn_close = tk.Button(main_frame, text="我知道了", command=self.window.destroy, width=15)
        btn_close.pack(pady=(15, 0))