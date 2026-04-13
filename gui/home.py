import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, ttk
import subprocess
import os
import sys
import socket
from config import HOST, PORT, VERTEX, EDGE, RECORD, TotalBytes, SendBytes, RecvBytes, Ipaddr, Degree, EdgeBytes, EdgeRecord, SrcIP, DstIP, SrcPort, DstPort, RecordBytes, RecordDuration
from daemon_server import DaemonConnection
from select_file import SelectWindow

# 设置窗口弹出的位置
POP_X = 300
POP_Y = 200

class NetworkApp:

    def __init__(self, root, server):
        self.root = root
        self.server = server
        self.create_UI(root, server) # 创建主页面

        # 记录用户筛选设置
        self.select_any_ip = ""
        self.select_src_ip = ""
        self.select_dst_ip = ""
        self.select_src_port = ""
        self.select_dst_port = ""

        self.tcp = True
        self.udp = True
        self.icmp = True
        self.other = True

        # 记录查找标记行
        self.matches = []
        self.curr_match = 0

        self.data = [] # 用来显示的data list
        self.mode = VERTEX # 类属性mode还是定义出来

    # =============== 主页面UI及数据排序主模块 =================

    def create_UI(self, root, server):
        self.root.title("网络流量分析系统")
        self.root.geometry("600x450")

        # 创建一个主框架来统一管理页边距
        main_frame = tk.Frame(root)
        main_frame.pack(padx=30, pady=10, fill=tk.BOTH, expand=True)

        # 1. 第一行，模式选择区域 - 全部居左
        mode_frame = tk.Frame(main_frame)
        mode_frame.pack(pady=5, fill=tk.X, anchor='w')  # anchor='w' 确保左对齐

        self.btn_vertex = tk.Button(mode_frame, text="ip节点视图", command=lambda: self.sort_command(VERTEX, TotalBytes, "mode"))
        self.btn_vertex.pack(side=tk.LEFT, padx=5)

        self.btn_edge = tk.Button(mode_frame, text="连接视图", command=lambda: self.sort_command(EDGE, EdgeBytes, "mode"))
        self.btn_edge.pack(side=tk.LEFT, padx=5)

        self.btn_record = tk.Button(mode_frame, text="记录视图", command=lambda: self.sort_command(RECORD, RecordBytes, "mode"))
        self.btn_record.pack(side=tk.LEFT, padx=5)

        self.btn_help = tk.Button(mode_frame, text="一点提示", command=lambda: self.show_help())
        self.btn_help.pack(side=tk.RIGHT, padx=5)

        # 2. 第二行，ip查找输入框
        search_frame = tk.Frame(main_frame)
        search_frame.pack(pady=5, fill=tk.X)  # fill=tk.X 让框架填满水平空间

        # 左侧：文本输入框和查找按钮（居左）
        left_search_frame = tk.Frame(search_frame)
        left_search_frame.pack(side=tk.LEFT)

        self.search_entry = tk.Entry(left_search_frame, width=50)
        self.search_entry.pack(side=tk.LEFT, padx=5)

        self.search_entry.insert(0, "查找ip地址...")
        self.search_entry.config(fg="grey", font=("Microsoft YaHei", 9))
        self.search_entry.bind("<FocusIn>", self.search_entry_click)
        self.search_entry.bind("<FocusOut>", self.search_entry_leave)

        self.search_entry.bind("<Return>", lambda: self.run_search())

        self.btn_search = tk.Button(left_search_frame, text="查找", command=self.run_search)
        self.btn_search.pack(side=tk.LEFT, padx=5)
        
        self.btn_search = tk.Button(left_search_frame, text="↑", command=lambda: self.run_search_see("up"))
        self.btn_search.pack(side=tk.LEFT)
        self.btn_search = tk.Button(left_search_frame, text="↓", command=lambda: self.run_search_see("down"))
        self.btn_search.pack(side=tk.LEFT)

        # 右侧：筛选按钮（居右）
        right_search_frame = tk.Frame(search_frame)
        right_search_frame.pack(side=tk.RIGHT)

        self.btn_filter = tk.Button(right_search_frame, text="筛选...", command=self.filter_popup)
        self.btn_filter.pack(side=tk.RIGHT, padx=5)  # 注意这里用 side=tk.RIGHT 使其靠右

        # 3. 第三行，结果显示区域
        self.create_Treeview(main_frame)

        # 4. 第四行，功能区
        extend_frame = tk.Frame(main_frame)
        extend_frame.pack(pady=5, fill=tk.X)

        # 左侧：重新选择文件按钮（居左）
        left_extend_frame = tk.Frame(extend_frame)
        left_extend_frame.pack(side=tk.LEFT)

        self.btn_reselect = tk.Button(left_extend_frame, text="重新选择文件", command=lambda: self.reselect_file(server))
        self.btn_reselect.pack(side=tk.LEFT, padx=5) 

        # 中间：状态统计标签
        self.lbl_status = tk.Label(left_extend_frame, text="正在加载数据...", fg="#555555", font=("Microsoft YaHei", 9))
        self.lbl_status.pack(side=tk.LEFT, padx=20)

        # 右侧
        right_extend_frame = tk.Frame(extend_frame)
        right_extend_frame.pack(side=tk.RIGHT)

        self.extend_combo = ttk.Combobox(right_extend_frame, 
                                        values=["路径查找", "星状结构", "安全规则检测", "子图可视化"],
                                        state="readonly",
                                        width=12,
                                        style='Extend.TCombobox')
        self.extend_combo.pack(side=tk.RIGHT, padx=5)
        self.extend_combo.set("扩展功能")

        # 绑定下拉框选择事件
        self.extend_combo.bind('<<ComboboxSelected>>', self.on_extend_select)
        # 要求：在结果显示区域以下再创建一个可以下拉的选择框，居右，文本是 "扩展功能"，点击后，显示一些选项，分别是："路径查找"，"星状结构"
        
        # 绑定关闭窗事件
        self.root.protocol("WM_DELETE_WINDOW", lambda: self.on_closing(server))

    def create_Treeview(self, main_frame):
        # 【关键修改】创建一个专门的子 Frame 来容纳表格和滚动条
        # 这样可以在这个子 Frame 内部自由使用 grid，而主 Frame 继续使用 pack
        tree_container = tk.Frame(main_frame)
        tree_container.pack(pady=10, fill=tk.BOTH, expand=True) # 使用 pack 填充剩余空间

        # --- 创建 Treeview (表格) ---
        columns = ("col1", "col2", "col3", "col4", "col5", "col6", "col7")
        self.tree = ttk.Treeview(tree_container, columns=columns, show='headings')
        # 定义高亮标签的样式（背景浅蓝色，字体黑色）
        self.tree.tag_configure('highlight', background='#87CEFA', foreground='black')

        # --- 添加滚动条 ---
        scrollbar_y = ttk.Scrollbar(tree_container, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar_x = ttk.Scrollbar(tree_container, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        # 在 tree_container 内部使用 grid 布局表格和滚动条
        self.tree.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        scrollbar_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        scrollbar_x.grid(row=1, column=0, sticky=(tk.E, tk.W))

        # 让 tree_container 内部的网格自适应
        tree_container.rowconfigure(0, weight=1)
        tree_container.columnconfigure(0, weight=1)

        # 创建右键菜单对象 (tearoff=0 表示去掉顶部的虚线分割条)
        # 1. IP节点视图菜单 (只有1个IP)
        self.context_menu_vertex = tk.Menu(self.root, tearoff=0)
        self.context_menu_vertex.add_command(label="复制整行", command=self.copy_row)
        self.context_menu_vertex.add_command(label="复制 IP 地址", command=lambda: self.copy_ip(0)) # 传入 0 代表提取第 1 列的数据
        self.context_menu_vertex.add_separator()
        # >>> 新增：快捷筛选与恢复
        self.context_menu_vertex.add_command(label="追踪 IP (一键筛选)", command=lambda: self.quick_filter_ip(0))
        self.context_menu_vertex.add_command(label="恢复默认视图 (取消筛选)", command=self.quick_reset_filter)

        # 2. 会话/记录视图菜单 (有 src_ip 和 dst_ip)
        self.context_menu_edge_record = tk.Menu(self.root, tearoff=0)
        self.context_menu_edge_record.add_command(label="复制整行", command=self.copy_row)
        self.context_menu_edge_record.add_command(label="复制 源 IP (src_ip)", command=lambda: self.copy_ip(0))
        self.context_menu_edge_record.add_command(label="复制 目的 IP (dst_ip)", command=lambda: self.copy_ip(1))
        self.context_menu_edge_record.add_separator()
        self.context_menu_edge_record.add_command(label="追踪 源 IP (一键筛选)", command=lambda: self.quick_filter_ip(0))
        self.context_menu_edge_record.add_command(label="追踪 目的 IP (一键筛选)", command=lambda: self.quick_filter_ip(1))
        self.context_menu_edge_record.add_command(label="恢复默认视图 (取消筛选)", command=self.quick_reset_filter)
        
        # 绑定右键点击事件 (<Button-3> 是鼠标右键)
        self.tree.bind("<Button-3>", self.show_menu)

        # 注意：这里不需要调用 self.load_tree_data(self.data)，因为初始化时 data 是空的

    def load_tree_data(self, data, mode):
        # 对不同的模式，用不同的表头
        if mode == VERTEX:
            self.tree["displaycolumns"] = ("col1", "col2", "col3", "col4", "col5", "col6")
            # --- 配置表头 (Headings) ---
            self.tree.heading("col1", text="IP地址", command=lambda: self.sort_command(VERTEX, Ipaddr, 'key'))
            self.tree.heading("col2", text="总流量 (Bytes)", command=lambda: self.sort_command(VERTEX, TotalBytes, 'key'))
            self.tree.heading("col3", text="总发送流量", command=lambda: self.sort_command(VERTEX, SendBytes, 'key'))
            self.tree.heading("col4", text="总接收流量", command=lambda: self.sort_command(VERTEX, RecvBytes, 'key'))
            self.tree.heading("col5", text="单向输出比", command=self.ratio_popup)
            self.tree.heading("col6", text="邻点个数", command=lambda: self.sort_command(VERTEX, Degree, 'key'))

            # --- 配置列宽和对齐方式 ---
            self.tree.column("col1", width=100, anchor=tk.W)
            self.tree.column("col2", width=65, anchor=tk.W)
            self.tree.column("col3", width=45, anchor=tk.W)
            self.tree.column("col4", width=45, anchor=tk.W)
            self.tree.column("col5", width=40, anchor=tk.W)
            self.tree.column("col6", width=30, anchor=tk.W)

        elif mode == EDGE:
            self.tree["displaycolumns"] = ("col1", "col2", "col3", "col4", "col5")
            self.tree.heading("col1", text="源 IP", command=lambda: self.sort_command(EDGE, SrcIP, 'key'))
            self.tree.heading("col2", text="目的 IP", command=lambda: self.sort_command(EDGE, DstIP, 'key'))
            self.tree.heading("col3", text="总流量 (Bytes)", command=lambda: self.sort_command(EDGE, EdgeBytes, 'key'))
            self.tree.heading("col4", text="总持续时长 (s)", command="")
            self.tree.heading("col5", text="会话次数", command=lambda: self.sort_command(EDGE, EdgeRecord, 'key'))

            # --- 配置列宽和对齐方式 ---
            self.tree.column("col1", width=100, anchor=tk.W)
            self.tree.column("col2", width=100, anchor=tk.W)
            self.tree.column("col3", width=70, anchor=tk.W)
            self.tree.column("col4", width=70, anchor=tk.W)
            self.tree.column("col5", width=30, anchor=tk.W)

        elif mode == RECORD:
            self.tree["displaycolumns"] = ("col1", "col2", "col3", "col4", "col5", "col6", "col7")
            self.tree.heading("col1", text="源 IP", command=lambda: self.sort_command(RECORD, SrcIP, 'key'))
            self.tree.heading("col2", text="目的 IP", command=lambda: self.sort_command(RECORD, DstIP, 'key'))
            self.tree.heading("col3", text="协议", command="")
            self.tree.heading("col4", text="源端口", command=lambda: self.sort_command(RECORD, SrcPort, 'key'))
            self.tree.heading("col5", text="目的端口", command=lambda: self.sort_command(RECORD, DstPort, 'key'))
            self.tree.heading("col6", text="流量 (Bytes)", command=lambda: self.sort_command(RECORD, RecordBytes, 'key'))
            self.tree.heading("col7", text="持续时间", command=lambda: self.sort_command(RECORD, RecordDuration, 'key'))
            
            # --- 配置列宽 ---
            self.tree.column("col1", width=105, anchor=tk.W)
            self.tree.column("col2", width=105, anchor=tk.W)
            self.tree.column("col3", width=40, anchor=tk.CENTER)
            self.tree.column("col4", width=60, anchor=tk.CENTER)
            self.tree.column("col5", width=60, anchor=tk.CENTER)
            self.tree.column("col6", width=80, anchor=tk.W)
            self.tree.column("col7", width=75, anchor=tk.W)

        else:
            messagebox.showerror("load_tree_data", f"数据显示加载出错，mode={mode}")

        # 更新统计标签文本
        if mode == VERTEX:
            view_name = "IP 节点"
        elif mode == EDGE:
            view_name = "连接"
        elif mode == RECORD:
            view_name = "记录"
        else:
            view_name = "未知"
            
        # len(data) 就是 C 传回来的行数
        self.lbl_status.config(text=f"当前视图: {view_name}  |  共计 {len(data)} 条记录")

        # 清空现有数据
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # 插入新数据
        for row in data:
            # 如果 row 是字符串列表，直接传入；如果是单个字符串，需自行拆分
            # 假设 row 已经是 ['val1', 'val2', ...] 格式
            self.tree.insert("", tk.END, values=row)

    def sort_command(self, sort_mode, sort_key, sort_change):

        self.mode = sort_mode
        # 切换排序模式的指令
        request = {
            "command": "APPLY_SORT",
            "payload": {
                "mode": sort_mode,              # 顶点/边/记录 模式
                "key": sort_key,                # 根据什么排序
                "change": sort_change           # 修改了什么变量
            }
        }
        data = self.send_and_receive(request) # 这里返回收到的数据

        if len(data) == 0: # 设置没有更改，所以不用改动页面
            print("不用更改页面")
            return
            
        print("排序加载成功")
        self.data = data
        self.load_tree_data(self.data, sort_mode)

    def send_and_receive(self, request):
        try:
            self.server.connect_daemon()
            self.server.send_daemon(request)
            
            # UI提示
            anime_frame = tk.Frame(self.root)
            anime_frame.pack(pady=(0, 10))
            loading_anime = tk.Label(anime_frame, text="正在加载排序...")
            loading_anime.grid(row=0, column=0, padx=5)
            self.root.update()

            print("sort 等待 Daemon 响应...")
            result = self.server.recv_daemon(timeout=10)

            # 消掉UI提示
            if loading_anime:
                loading_anime.destroy()
            if anime_frame:
                anime_frame.destroy()
            self.root.update()

            if result.get("status") != "success":
                raise Exception(result.get("message"))
            else:
                return result.get("data")
            
        except Exception as e:
            messagebox.showerror("通信错误", f"详情: {str(e)}")
        finally:
            # 用完直接关掉
            self.server.cut_daemon_connection()

    def show_help(self):
        from help_window import HelpWindow
        """弹出帮助手册窗口"""
        # 检查是否已经存在且未被销毁
        if hasattr(self, 'help_win') and self.help_win.window.winfo_exists():
            # 如果窗口已经打开了，就把它提到最前面，不重复创建
            self.help_win.window.lift()
            self.help_win.window.focus_force()
            return
            
        from help_window import HelpWindow
        # 必须赋值给 self.help_win，防止被垃圾回收！
        self.help_win = HelpWindow(self.root)

    # =============== 辅助功能模块 =================

    # 单向输出比限制
    def ratio_popup(self):
        # 创建一个置顶的子窗口 (Toplevel)
        popup = tk.Toplevel(self.root)
        popup.title("筛选发出占比")
        popup.geometry("250x130") # 稍微调高一点，腾出按钮空间
        popup.grab_set() # 模态窗口，必须关掉它才能点后面的界面

        # 提示文字
        tk.Label(popup, text="单项输出比 (0.0 ~ 1.0):").pack(pady=5)

        # 输入框
        entry = tk.Entry(popup, width=15)
        entry.pack(pady=5)
        # 给个贴心提示，比如默认是 0.8
        entry.insert(0, "0.8") 

        # 给函数增加一个 is_default 参数，用来判断是不是点击了“恢复默认”
        def apply_ratio(is_default=False):
            if is_default:
                threshold = 0.0
                # 贴心细节：点击恢复默认后，把输入框的字也改成 0.0
                entry.delete(0, tk.END)
                entry.insert(0, "0.0")
            else:
                val = entry.get().strip()
                if not val: # 如果为空，默认恢复不筛选 (0)
                    threshold = 0.0
                else:
                    try:
                        # 转换成小数
                        threshold = float(val)
                        # 可以顺手加个范围校验
                        if threshold < 0.0 or threshold > 1.0:
                            messagebox.showwarning("提示", "请输入 0.0 到 1.0 之间的数值！")
                            return
                    except ValueError:
                        messagebox.showerror("错误", "请输入有效的数字！")
                        return
            
            # 封装请求，发给 daemon_server
            request = {
                "command": "APPLY_RATIO_FILTER",
                "payload": {
                    "threshold": threshold
                }
            }

            try:
                self.data = self.send_and_receive(request) 
                self.load_tree_data(self.data, self.mode)
                
                if len(self.data) == 0:
                    messagebox.showinfo("筛选结果", f"当前阈值 {threshold} 筛选下没有结果！")
                    # 同样，不执行 popup.destroy()，留着窗口让他改
                else:
                    print(f"ratio 筛选加载成功，当前阈值: {threshold}")
                    popup.destroy() # 关闭弹窗
                    
            except Exception as e:
                messagebox.showerror("ratio错误", f"应用筛选条件失败: {e}")

        # --- 修复按钮布局 ---
        # 1. 创建 Frame 并独立 pack，这样 button_frame 才是一个真正的框
        button_frame = tk.Frame(popup)
        button_frame.pack(pady=10)

        # 2. 在 button_frame 里放入两个按钮，用 side=tk.LEFT 让它们在同一行从左到右排
        btn_default = tk.Button(button_frame, text="恢复默认", command=lambda: apply_ratio(is_default=True))
        btn_default.pack(side=tk.LEFT, padx=10) # padx 增加按钮间距

        btn_confirm = tk.Button(button_frame, text="确认筛选", command=lambda: apply_ratio(is_default=False))
        btn_confirm.pack(side=tk.LEFT, padx=10)

    # 筛选相关功能
    def filter_popup(self):
        self.config = tk.Toplevel(self.root)
        self.config.title("筛选设置")
        
        # 设定窗口大小，不贴边放置
        window_width = 450
        window_height = 350
        # 刷新窗口以获取准确的屏幕尺寸
        self.config.geometry(f"{window_width}x{window_height}+300+200")

        # 禁止用户操作主窗口
        self.config.transient(self.root) 

        # 创建一个主 Frame 来容纳所有内容，控制四周的 padx=20 和 pady=20
        main_frame = tk.Frame(self.config)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # 为了让文本框垂直对齐，统一设置 Label 的宽度
        label_width = 8
        
        # 第 0 行 any_ip (双向包含 IP)
        row0 = tk.Frame(main_frame)
        row0.pack(fill=tk.X, pady=8)
        tk.Label(row0, text="包含 IP:", width=label_width, anchor='w').pack(side=tk.LEFT)
        self.any_ip_entry = tk.Entry(row0, width=40)
        self.any_ip_entry.pack(side=tk.LEFT, padx=10)
        self.any_ip_entry.insert(0, self.select_any_ip)

        # 1. 第一行 src_ip (长文本框)
        row1 = tk.Frame(main_frame)
        row1.pack(fill=tk.X, pady=8) # 行与行之间留点上下间距
        tk.Label(row1, text="源 IP:", width=label_width, anchor='w').pack(side=tk.LEFT)
        self.src_ip_entry = tk.Entry(row1, width=40)
        self.src_ip_entry.pack(side=tk.LEFT, padx=10)
        self.src_ip_entry.insert(0, self.select_src_ip)

        # 2. 第二行 dst_ip (长文本框)
        row2 = tk.Frame(main_frame)
        row2.pack(fill=tk.X, pady=8)
        tk.Label(row2, text="目标 IP:", width=label_width, anchor='w').pack(side=tk.LEFT)
        self.dst_ip_entry = tk.Entry(row2, width=40)
        self.dst_ip_entry.pack(side=tk.LEFT, padx=10)
        self.dst_ip_entry.insert(0, self.select_dst_ip)

        # 3. 第三行 protocol (打勾的选项框)
        row3 = tk.Frame(main_frame)
        row3.pack(fill=tk.X, pady=8)
        tk.Label(row3, text="协议:", width=label_width, anchor='w').pack(side=tk.LEFT)
        
        # 记录勾选状态的变量
        self.var_tcp = tk.BooleanVar(value=self.tcp)
        self.var_udp = tk.BooleanVar(value=self.udp)
        self.var_icmp = tk.BooleanVar(value=self.icmp)
        self.var_other = tk.BooleanVar(value=self.other)

        tk.Checkbutton(row3, text="TCP(6)", variable=self.var_tcp).pack(side=tk.LEFT, padx=(10, 5))
        tk.Checkbutton(row3, text="UDP(17)", variable=self.var_udp).pack(side=tk.LEFT, padx=5)
        tk.Checkbutton(row3, text="ICMP(1)", variable=self.var_icmp).pack(side=tk.LEFT, padx=5)
        tk.Checkbutton(row3, text="其它", variable=self.var_other).pack(side=tk.LEFT, padx=5)

        # 4. 第四行 src_port 
        row4 = tk.Frame(main_frame)
        row4.pack(fill=tk.X, pady=8)
        tk.Label(row4, text="src_port:", width=label_width, anchor='w').pack(side=tk.LEFT)
        self.src_port_entry = tk.Entry(row4, width=20)
        self.src_port_entry.pack(side=tk.LEFT, padx=10)
        self.src_port_entry.insert(0, self.select_src_port)

        # 5. 第五行 dst_port 
        row5 = tk.Frame(main_frame)
        row5.pack(fill=tk.X, pady=8)
        tk.Label(row5, text="dst_port:", width=label_width, anchor='w').pack(side=tk.LEFT)
        self.dst_port_entry = tk.Entry(row5, width=20)
        self.dst_port_entry.pack(side=tk.LEFT, padx=10)
        self.dst_port_entry.insert(0, self.select_dst_port)

        # 6. 第六行 按钮区域 (左边恢复默认，右边确认/取消)
        row6 = tk.Frame(main_frame)
        # 距离上面的输入框留出大一点的间隔 (pady=(20, 0) 表示上方20，下方0)
        row6.pack(fill=tk.X, pady=(20, 0)) 

        # 左侧按钮
        self.btn_reset = tk.Button(row6, text="恢复默认设置", command=self.reset_filter)
        self.btn_reset.pack(side=tk.LEFT)

        # 右侧创建一个小框架容纳确认和取消按钮，使它们靠右对齐
        right_btn_frame = tk.Frame(row6)
        right_btn_frame.pack(side=tk.RIGHT)

        self.btn_confirm = tk.Button(right_btn_frame, text="确认", command=self.apply_filter, width=8)
        self.btn_confirm.pack(side=tk.LEFT, padx=5)

        self.btn_cancel = tk.Button(right_btn_frame, text="取消", command=self.config.destroy, width=8)
        self.btn_cancel.pack(side=tk.LEFT, padx=(5, 0))

    def reset_filter(self):
        """恢复默认设置逻辑"""
        self.any_ip_entry.delete(0, tk.END)
        self.src_ip_entry.delete(0, tk.END)
        self.dst_ip_entry.delete(0, tk.END)
        self.src_port_entry.delete(0, tk.END)
        self.dst_port_entry.delete(0, tk.END)
        self.var_tcp.set(True)
        self.var_udp.set(True)
        self.var_icmp.set(True)
        self.var_other.set(True)
        print("已恢复默认设置")
        self.apply_filter()

    def apply_filter(self):
        """确认筛选逻辑"""
        # 获取输入的 IP
        self.select_any_ip = self.any_ip_entry.get().strip()
        self.select_src_ip = self.src_ip_entry.get().strip()
        self.select_dst_ip = self.dst_ip_entry.get().strip()
        
        # 获取并校验端口（如果不是数字，转成 -1 代表不筛选）
        self.select_src_port = self.src_port_entry.get().strip()
        src_port = int(self.select_src_port) if self.select_src_port.isdigit() else -1
        
        self.select_dst_port = self.dst_port_entry.get().strip()
        dst_port = int(self.select_dst_port) if self.select_dst_port.isdigit() else -1

        # 记录一下协议筛选值
        self.tcp = self.var_tcp.get()
        self.udp = self.var_udp.get()
        self.icmp = self.var_icmp.get()
        self.other = self.var_other.get()

        # 封装请求发送给 Daemon
        request = {
            "command": "APPLY_ADVANCED_FILTER",
            "payload": {
                "any_ip": self.select_any_ip,
                "src_ip": self.select_src_ip,
                "dst_ip": self.select_dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "tcp": self.tcp,
                "udp": self.udp,
                "icmp": self.icmp,
                "other": self.other
            }
        }
        
        try:
            # 连接服务器，获取 C 程序的返回值
            self.data = self.send_and_receive(request)
            self.load_tree_data(self.data, self.mode)

            # 2. 判断是不是空结果
            if len(self.data) == 0:
                messagebox.showinfo("筛选结果", "没有找到符合当前筛选条件的记录！\n请调整筛选条件。")
                # 注意：不要关闭筛选弹窗，让用户留在弹窗里继续修改他刚才输入的条件！
            else:
                print("筛选条件加载成功！")
                self.config.destroy() # 如果有数据，才关闭筛选子窗口

        except Exception as e:
            messagebox.showerror("筛选错误", f"应用筛选条件失败: {e}")
            
        # 关掉子窗口
        # self.config.destroy()

    # 查找相关功能
    def run_search(self):
        # 1. 获取输入框的内容并去除两端空格
        keyword = self.search_entry.get().strip()
        if not keyword:
            messagebox.showwarning("提示", "请输入要查找的 IP 或关键字")
            return

        print(f"正在查找: {keyword}")
        
        # 2. 清除之前的所有高亮状态
        for item in self.tree.get_children():
            self.tree.item(item, tags=()) # 清空 tag 即可恢复原状

        self.matches.clear()
        first_match = None
        match_count = 0

        # 3. 遍历表格中的所有行
        for item in self.tree.get_children():
            values = self.tree.item(item, 'values')
            if not values:
                continue

            is_match = False
            
            # 根据当前模式决定匹配逻辑
            if self.mode == VERTEX:
                # Vertex 模式：只看第 1 列 (IP 地址)
                if keyword in str(values[0]):
                    is_match = True
            else:
                # Edge 或 Record 模式：看第 1 列 (源IP) 或 第 2 列 (目的IP)
                if keyword in str(values[0]) or keyword in str(values[1]):
                    is_match = True

            # 4. 如果匹配成功，打上高亮标签
            if is_match:
                self.tree.item(item, tags=('highlight',))
                match_count += 1
                self.matches.append(item)
                if first_match is None:
                    first_match = item # 记录找到的第一个结果

        # 5. 交互反馈
        if first_match:
            # 滚动表格，确保第一条匹配的行显示在视口中
            self.tree.see(first_match)
            self.curr_match = 0
            # 可选：选中第一条匹配的行
            self.tree.selection_set(first_match)
            # 在底部控制台或者用弹窗提示结果（为了不烦人，这里建议不用弹窗，或者只在标题栏提示）
            self.root.title(f"网络流量分析系统 - 查找到 {match_count} 条关于 '{keyword}' 的结果")
        else:
            messagebox.showinfo("查找结果", f"未找到包含 '{keyword}' 的记录。")

    def run_search_see(self, order):
        match_count = len(self.matches)
        if order == "up":
            if self.curr_match == 0:
                return
            else:
                self.curr_match-=1
                self.tree.selection_set(self.matches[self.curr_match])
                self.tree.see(self.matches[self.curr_match])
        elif order == "down":
            if self.curr_match == match_count-1:
                return
            else:
                self.curr_match+=1
                self.tree.selection_set(self.matches[self.curr_match])
                self.tree.see(self.matches[self.curr_match])
        else:
            messagebox.showerror("run_search_see",f"出现未识别order{order}")

    def search_entry_click(self, event):
        if self.search_entry.get() == "查找ip地址...":
        # 如果当前内容是提示语，则清空并变黑
            self.search_entry.delete(0, tk.END)
            self.search_entry.config(fg="black")

    def search_entry_leave(self, event):
        if not self.search_entry.get():
            # 如果用户没输入任何内容，恢复提示语和灰色
            self.search_entry.insert(0, "查找ip地址...")
            self.search_entry.config(fg="grey", font=("Microsoft YaHei", 9))

    # 右键相关功能
    def show_menu(self, event):
        """显示右键菜单 event: 鼠标事件对象，包含 x, y 坐标"""
        # 1. 确定用户右键点击了哪一行
        item_id = self.tree.identify_row(event.y)
        
        if item_id:
            # a. 选中这一行 (视觉反馈，让用户知道操作的是哪一行)
            self.tree.selection_set(item_id)
            
            # b. 记录当前选中的 item_id 到实例变量
            self.selected_item = item_id
            
            # c. 在鼠标当前位置弹出菜单
            try:
                # 核心修改：根据模式弹出不同的菜单
                if self.mode == VERTEX:
                    self.context_menu_vertex.post(event.x_root, event.y_root)
                else: # EDGE 或 RECORD 模式
                    self.context_menu_edge_record.post(event.x_root, event.y_root)
            except Exception as e:
                print(f"菜单弹出失败: {e}")

    def copy_row(self):
        """复制选中行的所有数据"""
        if hasattr(self, 'selected_item') and self.selected_item:
            values = self.tree.item(self.selected_item, 'values')
            if values:
                # 将该行的各个列数据用 制表符(\t) 拼接，方便直接粘贴到 Excel 等表格软件中
                row_text = " ".join(str(v) for v in values)
                self.root.clipboard_clear()
                self.root.clipboard_append(row_text)
                print(f"已复制整行: {row_text}")

    def copy_ip(self, col_index):
        """
        执行复制 IP 的操作
        col_index: 0代表提取第1列(通常是src_ip或单独的IP)，1代表提取第2列(通常是dst_ip)
        """
        if hasattr(self, 'selected_item') and self.selected_item:
            # 1. 获取选中行的所有数据 (返回的是一个元组 tuple)
            values = self.tree.item(self.selected_item, 'values')
            
            # 2. 提取指定的 IP 地址 (根据传入的列索引)
            if values and len(values) > col_index:
                ip_address = str(values[col_index])
                
                # 3. 写入系统剪贴板
                self.root.clipboard_clear()       # 先清空剪贴板
                self.root.clipboard_append(ip_address) # 再写入新内容
                
                print(f"已复制 IP: {ip_address}")

    def quick_filter_ip(self, col_index):
        """右键快捷功能：将选中的 IP 设为全局 any_ip 进行筛选"""
        if hasattr(self, 'selected_item') and self.selected_item:
            values = self.tree.item(self.selected_item, 'values')
            if values and len(values) > col_index:
                ip_address = str(values[col_index])
                
                # 1. 更新实例变量（保证打开筛选弹窗时状态是对的）
                self.select_any_ip = ip_address
                self.select_src_ip = ""
                self.select_dst_ip = ""
                self.select_src_port = ""
                self.select_dst_port = ""
                self.tcp = self.udp = self.icmp = self.other = True
                
                # 2. 组装请求发给 Daemon (复用你写好的底层指令)
                request = {
                    "command": "APPLY_ADVANCED_FILTER",
                    "payload": {
                        "any_ip": self.select_any_ip,
                        "src_ip": "-",
                        "dst_ip": "-",
                        "src_port": -1,
                        "dst_port": -1,
                        "tcp": 1, "udp": 1, "icmp": 1, "other": 1
                    }
                }
                
                # 3. 发送请求并刷新页面
                try:
                    self.data = self.send_and_receive(request)
                    self.load_tree_data(self.data, self.mode)
                    print(f"已一键追踪 IP: {ip_address}")
                    
                    # 贴心的小优化：修改状态栏提示，让用户知道当前处于筛选状态
                    current_title = self.root.title()
                    self.root.title(f"网络流量分析系统 - [当前已过滤: {ip_address}]")
                except Exception as e:
                    messagebox.showerror("筛选错误", f"应用一键筛选失败: {e}")

    def quick_reset_filter(self):
        """右键快捷功能：一键恢复所有默认筛选条件"""
        # 1. 重置所有实例变量
        self.select_any_ip = ""
        self.select_src_ip = ""
        self.select_dst_ip = ""
        self.select_src_port = ""
        self.select_dst_port = ""
        self.tcp = self.udp = self.icmp = self.other = True
        
        # 2. 组装恢复默认的请求 (全是默认值)
        request = {
            "command": "APPLY_ADVANCED_FILTER",
            "payload": {
                "any_ip": "-",
                "src_ip": "-",
                "dst_ip": "-",
                "src_port": -1,
                "dst_port": -1,
                "tcp": 1, "udp": 1, "icmp": 1, "other": 1
            }
        }
        
        # 3. 发送请求并刷新页面
        try:
            self.data = self.send_and_receive(request)
            self.load_tree_data(self.data, self.mode)
            print("已恢复默认视图")
            
            # 恢复原标题
            self.root.title("网络流量分析系统")
        except Exception as e:
            messagebox.showerror("恢复错误", f"恢复默认视图失败: {e}")

    # =============== 扩展功能模块 =================

    def on_extend_select(self, event=None):
        """处理扩展功能选择事件"""
        selected = self.extend_combo.get()
        
        if selected == "路径查找":
            print("正在打开路径查找页面")
            try:
                self.open_path_find_window()
            except Exception as e:
                messagebox.showerror("拓展功能打开出错", f"无法启动后台服务: {e}")
                return # 跳出函数
                
        elif selected == "星状结构":
            print("正在打开星状结构页面")
            try:
                self.open_star_structure_window()
            except Exception as e:
                messagebox.showerror("拓展功能打开出错", f"无法启动后台服务: {e}")
                return # 跳出函数
            
        elif selected == "安全规则检测":
            try:
                self.open_security_rule_window()
            except Exception as e:
                messagebox.showerror("错误", str(e))
                return
            
        elif selected == "子图可视化":
            try:
                self.open_graph_vis_window()
            except Exception as e:
                messagebox.showerror("错误", str(e))
                return
            
        # 动作执行完后，把下拉框的文字恢复为默认的 "扩展功能"
        self.extend_combo.set("扩展功能")

    def open_path_find_window(self):
        """弹出路径查找窗口"""
        # 检查是否已经存在且未被销毁
        if hasattr(self, 'path_win') and self.path_win.window.winfo_exists():
            # 如果窗口已经打开了，就把它提到最前面，不重复创建
            self.path_win.window.lift()
            self.path_win.window.focus_force()
            return
            
        # 【关键修改】：必须赋值给 self.path_win，防止被垃圾回收！
        from path_find_window import PathFindWindow
        self.path_win = PathFindWindow(self.root, self.server) 

    def open_star_structure_window(self):
        """弹出星状结构窗口"""
        if hasattr(self, 'star_win') and self.star_win.window.winfo_exists():
            self.star_win.window.lift()
            self.star_win.window.focus_force()
            return
            
        # 同样，必须赋值
        from star_structure_window import StarStructureWindow
        self.star_win = StarStructureWindow(self.root, self.server) 

    def open_security_rule_window(self):
        if hasattr(self, 'sec_win') and self.sec_win.window.winfo_exists():
            self.sec_win.window.lift()
            self.sec_win.window.focus_force()
            return
        from security_rule_window import SecurityRuleWindow
        self.sec_win = SecurityRuleWindow(self.root, self.server)
    
    def open_graph_vis_window(self):
        if hasattr(self, 'vis_win') and self.vis_win.window.winfo_exists():
            self.vis_win.window.lift()
            self.vis_win.window.focus_force()
            return
        from graph_vis_window import GraphVisWindow
        self.vis_win = GraphVisWindow(self.root, self.server)
        
    # =============== 更换页面/收尾模块 =================

    def reselect_file(self, server):
        if getattr(sys, 'frozen', False):
            # 打包环境下，直接无参数重启自己
            subprocess.Popen([sys.executable], 
                             creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)
        else:
            # 源码环境下，用 python 重新跑 script
            python = sys.executable
            script = os.path.abspath(__file__)
            subprocess.Popen([python, script], 
                             creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)
                             
        self.on_closing(server)

    def on_closing(self, server):
        try:
            # 先通知daemon关闭
            server.shut_daemon()
        except:
            pass
        finally:
            # 再关闭当前程序, 销毁窗口
            self.root.destroy()
            # 彻底退出 Python 进程
            sys.exit(0)

if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    # 只要发现启动参数里带有 "run_daemon"，立刻去跑后台，然后光荣牺牲，绝对不允许往下走画出窗口！
    if len(sys.argv) > 1 and sys.argv[1] == "run_daemon":
        # 防止 --windowed 模式下后台 print 报错导致进程崩溃
        sys.stdout = open(os.devnull, 'w')
        sys.stderr = open(os.devnull, 'w')
        
        import daemon_server
        daemon_server.get_exe_path()
        daemon_server.start_server()
        sys.exit(0) # 后台任务跑完直接退出！

    # select_file先运行，就直接在这里运行即可
    root = tk.Tk()
    try:
        server = DaemonConnection()
    except Exception as e:
        messagebox.showerror("服务器连接出错", f"收到错误信息{e}")

    select_file = SelectWindow(root, server)
    root.mainloop()

    root = tk.Tk()
    app = NetworkApp(root, server) # 创建一个这个应用的类，这个类叫app
    # 连接 Daemon 发送第一次加载指令
    try:
        app.sort_command(VERTEX, TotalBytes, "mode")
        print("初始化排序指令发送成功，建立GUI页面的同时等待C引擎相应")
    except socket.timeout:
        messagebox.showerror("超时", "C 引擎排序发送前超时 (超过60秒)。\n请检查")
    except Exception as e:
        import traceback
        traceback.print_exc()
        messagebox.showerror("通信错误2", f"详情: {str(e)}")
    root.mainloop()
