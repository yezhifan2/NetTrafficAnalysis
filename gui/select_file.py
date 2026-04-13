import tkinter as tk
from tkinter import scrolledtext, messagebox
from tkinter import filedialog  # >>> 新增：引入文件选择对话框工具
import subprocess
import socket
import json
import os
import sys
from config import HOST, PORT
from daemon_server import DaemonConnection

# 启动daemon
# 连接daemon，client_socket
# 发送loadfile请求->daemon那边打开C，传给C，C初始化回馈
# 启动home->home那边发送第一个默认排序给daemon，一个来回再输出到大屏上

class SelectWindow:
    def __init__(self, root, server):
        self.root = root
        self.create_UI(root, server)
        # 保存文件路径
        self.selected_file = None
        self.server_running = False

    def create_UI(self, root, server):
        self.root.title("网络流量分析系统")
        self.root.geometry("600x400+300+200")

        # 创建一个单独的盒子（Frame）来放文件选择的相关组件
        self.file_frame = tk.Frame(root)
        self.file_frame.pack(pady=150) # 其实这里可以改，这里是一个巨大的上下页边距，可以用fill和expand改成页面居中

        # 1. 标签（Label）：显示 "数据文件:" 这几个字
        lbl_file = tk.Label(self.file_frame, text="数据文件:")
        lbl_file.grid(row=0, column=0, padx=5)

        # 2. 输入框（Entry）：用来显示选中的文件路径
        # self.file_entry 让我们可以稍后在代码里读取或修改里面的文字
        self.file_entry = tk.Entry(self.file_frame, width=40) 
        self.file_entry.grid(row=0, column=1, padx=5)

        # 3. 浏览按钮（Button）：点击后触发 self.choose_file 函数
        btn_browse = tk.Button(self.file_frame, text="浏览...", command=self.choose_file)
        btn_browse.grid(row=0, column=2, padx=5)

        # 第二行：加载按钮 - 与文件浏览文本框右对齐
        self.load_frame = tk.Frame(self.file_frame)
        self.load_frame.grid(row=1, column=1, columnspan=2, pady=(5, 0), sticky='e')  # 从第1列开始，占2列，右对齐

        self.btn_load = tk.Button(self.load_frame, text="加载数据文件", command=lambda: self.confirm_and_launch(server))
        self.btn_load.pack(side=tk.RIGHT)  # 按钮在self.load_frame中右对齐

        # 绑定关闭窗事件
        self.root.protocol("WM_DELETE_WINDOW", lambda: self.on_closing(server))
    # =============== 以下是功能模块 =================

    def choose_file(self):
        # 1. 打开文件选择窗口，返回路径
        filename = filedialog.askopenfilename(
            title="选择流量数据文件", 
            filetypes=[
                ("所有支持的数据", "*.csv *.pcap *.pcapng"),  # 第一行：同时显示 csv 和 pcap
                ("CSV 文件 (.csv)", "*.csv"),       # 单独显示 csv
                ("PCAP 抓包文件", "*.pcap *.pcapng"), # 单独显示 pcap
                ("所有文件", "*.*")                 # 显示电脑里的一切文件
            ]
        )
        
        # 2. 如果用户选了文件，讲路径存储至self.selected_file
        if filename:
            self.file_entry.delete(0, tk.END)  # 清空输入框
            self.file_entry.insert(0, filename) # 填入新路径
            self.selected_file = filename

# home.py开启->打开daemon服务器->daemon打开exe, 创建监听端口
# home.py开启->打开select窗口
# select窗口中点击按钮->连接daemon，告诉daemon文件路径,daemon接收到LOAD_FILE指令，初始化exe
# select窗口中点击按钮->打开home page
# home主动连daemon，发送第一次的默认排序指令
# daemon和exe交互，再将信息返还给home窗口

    def confirm_and_launch(self, server):
        """确认选择并启动主程序"""
        if not self.selected_file:
            messagebox.showwarning("警告", "请先选择一个数据文件！")
            return
        if not os.path.exists(self.selected_file):
            messagebox.showerror("错误", f"文件不存在: {self.selected_file}")
            return
            
        # 设置发送数据
        request = {
            "command": "LOAD_FILE", # 注意：我改名叫 load_file 了，因为不仅是 launch
            "payload": {
                "file_path": self.selected_file
            }
        }

        # UI 提示
        self.anime_frame = tk.Frame(self.root)
        self.anime_frame.pack(pady=(0, 10))
        loading_anime = tk.Label(self.anime_frame, text="正在启动后台服务并加载数据...")
        loading_anime.grid(row=0, column=0, padx=5)
        self.root.update()

        status = False
        # 和服务器交互
        try:
            server.connect_daemon_mul()
            # 连接 Daemon 发送加载指令
            server.send_daemon(request)
            result = server.recv_daemon(timeout=10)
            if result.get("status") == "success":
                print("初始化加载成功")
                self.shift_page()
        except Exception as e:
            messagebox.showerror("服务器连接出错", f"收到错误信息{e}")
        finally:
            try:
                server.cut_daemon_connection()
            except:
                pass
            

    def shift_page(self):
        # 加载home，退出select
        print(f"home页面已启动")

        self.root.quit()
        self.root.destroy()
        print(f"select_file页面已退出")

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
    # 【核心修复：拦截无限弹窗】
    # 检查启动参数，如果是被子进程通过暗号 "run_daemon" 唤醒的，则直接运行后台逻辑并退出
    if len(sys.argv) > 1 and sys.argv[1] == "run_daemon":
        import daemon_server
        daemon_server.get_exe_path()
        daemon_server.start_server()
        sys.exit(0)  # 后台服务运行完毕/被关闭后，一定要退出，千万别往下执行 GUI 代码！

    root = tk.Tk()
    try:
        server = DaemonConnection()
    except Exception as e:
        messagebox.showerror("服务器连接出错", f"收到错误信息{e}")

    select_file = SelectWindow(root, server)
    root.mainloop()