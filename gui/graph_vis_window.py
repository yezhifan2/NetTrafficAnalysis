import tkinter as tk
from tkinter import scrolledtext, messagebox
import os

HTTP_SERVER_PORT = 8088       # 给本地服务器分配一个端口
HTTP_SERVER_STARTED = False   # 记录服务器是否已经启动

class GraphVisWindow:
    def __init__(self, root, server):
        self.server = server
        self.window = tk.Toplevel(root)
        self.window.title("子图可视化 (连通分量分析)")
        self.window.geometry("550x400+300+200")
        
        self.window.transient(root)
        self.window.lift()
        self.window.focus_force()
        
        main_frame = tk.Frame(self.window)
        main_frame.pack(padx=20, pady=15, fill=tk.BOTH, expand=True)

        info = ("【图可视化分析】\n"
                "利用 C 引擎的并查集算法，快速提取目标 IP 所在的连通子图，\n"
                "并自动在浏览器中生成交互式网络拓扑结构图。")
        tk.Label(main_frame, text=info, fg="#333333", justify=tk.LEFT).pack(anchor='w', pady=(0, 5))

        # 输入区域
        input_frame = tk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=5)

        tk.Label(input_frame, text="目标节点 IP:").pack(side=tk.LEFT, padx=(0, 5))
        self.ip_entry = tk.Entry(input_frame, width=20)
        self.ip_entry.pack(side=tk.LEFT, padx=5)

        self.btn_vis = tk.Button(input_frame, text="生成可视化拓扑图", command=self.run_visualization)
        self.btn_vis.pack(side=tk.LEFT, padx=15)

        # 结果显示区域
        tk.Label(main_frame, text="运行日志:").pack(anchor='w', pady=(5, 5))
        self.result_text = scrolledtext.ScrolledText(main_frame, width=60, height=8, bg="#F8F8F8")
        self.result_text.pack(fill=tk.BOTH, expand=True)

    def run_visualization(self):
        target_ip = self.ip_entry.get().strip()
        if not target_ip:
            messagebox.showwarning("提示", "请输入目标 IP！", parent=self.window)
            return

        self.btn_vis.config(state=tk.DISABLED, text="正在生成 HTML...")
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"正在向 C 引擎请求 {target_ip} 所在的并查集子图...\n")
        self.window.update()

        request = {
            "command": "VISUALIZE_GRAPH",
            "payload": {"target_ip": target_ip}
        }

        try:
            if not self.server.test_daemon():
                self.server.start_daemon()
            self.server.connect_daemon()
            self.server.send_daemon(request)
            result = self.server.recv_daemon(timeout=10)
            data = result.get("data",[])
            if result.get("status") != "success":
                self.result_text.insert(tk.END, f"\n生成失败: {result.get('message')}")
                raise Exception(result.get("message"))
            message = self.create_graph(result.get("data"))
            self.result_text.insert(tk.END, "\n" + message + "\n")
            self.result_text.insert(tk.END, "请在自动打开的浏览器中查看交互式拓扑图！")
        except Exception as e:
            messagebox.showerror("网络错误", f"无法连接后台:\n{e}", parent=self.window)
        finally:
            try:
                self.cut_daemon_connection()
            except:
                pass
            self.btn_vis.config(state=tk.NORMAL, text="生成可视化拓扑图")

    def start_local_http_server(self, directory):
        """启动一个后台微型 HTTP 服务器的终极稳妥版"""
        import http.server
        import socketserver
        import threading
        import functools
        
        global HTTP_SERVER_STARTED
        if HTTP_SERVER_STARTED:
            return
            
        try:
            # 【核心修复：防崩溃无声服务器】
            # 重写请求处理类，直接把打印日志的方法 pass 掉，让它彻底静默，防止打包后崩溃！
            class SilentHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
                def log_message(self, format, *args):
                    pass 
                    
            # 使用我们自定义的静默处理器
            Handler = functools.partial(SilentHTTPRequestHandler, directory=directory)
            
            socketserver.TCPServer.allow_reuse_address = True
            httpd = socketserver.TCPServer(("127.0.0.1", HTTP_SERVER_PORT), Handler)
            
            # 放入守护线程运行
            server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            server_thread.start()
            
            HTTP_SERVER_STARTED = True
        except Exception as e:
            HTTP_SERVER_STARTED = True # 标记为已启动，防止无限重复报错

    def create_graph(self, cmd_output):
        import networkx as nx
        from ipysigma import Sigma

        edges_found = 0
        G = nx.Graph() 
        
        # 【关键修复 1：无敌容错解析】防范 read_until_prompt 强行返回列表，导致节点变成 list
        for item in cmd_output:
            try:
                # 应对底层传来的是列表的情况 (如 ['[EDGE]192.168.1.1', '10.0.0.1', '500'])
                if isinstance(item, list) and len(item) >= 3:
                    first_part = str(item[0]).strip()
                    if first_part.startswith("[EDGE]"):
                        src = first_part.replace("[EDGE]", "").strip()
                        dst = str(item[1]).strip()
                        weight = float(item[2])
                        # 强制转为 str，绝对不让 list 混进节点里！
                        G.add_edge(str(src), str(dst), weight=weight)
                        edges_found += 1
                        
                # 应对底层传来的是正常字符串的情况
                elif isinstance(item, str):
                    line = item.strip()
                    if line.startswith("[EDGE]"):
                        parts = line.replace("[EDGE]", "").split(",")
                        if len(parts) >= 3:
                            src = parts[0].strip()
                            dst = parts[1].strip()
                            weight = float(parts[2])
                            G.add_edge(str(src), str(dst), weight=weight)
                            edges_found += 1
            except Exception:
                continue # 忽略个别解析失败的脏数据
                
        if edges_found == 0:
            response = {"status": "error", "message": "未找到该 IP，或该 IP 是孤立节点。"}
        else:
            # 1. 设置 HTML 生成路径（兼容打包环境）
            import sys
            import os
            
            if getattr(sys, 'frozen', False):
                # 如果是打包后的 EXE，强制将 HTML 生成在 EXE 同级目录下，绝对可读写
                base_dir = os.path.dirname(sys.executable)
            else:
                # 正常源码环境，放在当前代码的同级目录
                base_dir = os.path.dirname(os.path.abspath(__file__))
                
            html_filename = "subgraph_visual.html"
            html_path = os.path.join(base_dir, html_filename)
            
            # 2. 提前计算好节点的度数映射字典
            degree_dict = dict(G.degree)

            # 3. 使用 ipysigma 生成可视化
            # 【补丁 1】：强行指定 height，解决 "Container has no height" 报错
            sigma_graph = Sigma(
                G, 
                node_size=degree_dict, 
                node_color=degree_dict,
                height=800  # >>> 强制给画布一个 800px 的高度
            )
            sigma_graph.to_html(html_path)
            
            # ==========================================
            # 【补丁 2】：HTML 动态注入 (Surgical Patch)
            # 解决 ipysigma.js 404 找不到文件和核心组件加载崩溃的问题
            # ==========================================
            with open(html_path, 'r', encoding='utf-8') as f:
                html_content = f.read()

            # 注入国内的 jsdelivr CDN 加载路径，强行纠正它的依赖寻址
            injection = """
            <style>
                /* 双保险：强行撑开所有的 Jupyter 容器高度 */
                .sigma-container, .jupyter-widgets {
                    height: 800px !important;
                    min-height: 800px !important;
                }
            </style>
            <script>
                // 强行告诉 require.js 去国内 CDN 下载 ipysigma 核心依赖，绝不允许在本地找
                if (window.require && window.require.config) {
                    window.require.config({ paths: { "ipysigma": "https://cdn.jsdelivr.net/npm/ipysigma/dist/index" } });
                } else {
                    var require = { paths: { "ipysigma": "https://cdn.jsdelivr.net/npm/ipysigma/dist/index" } };
                }
            </script>
            """
            # 把这块补丁死死地打进 <head> 标签的最底部
            html_content = html_content.replace('</head>', injection + '\n</head>')

            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            # ==========================================
            
            # 4. 启动后台微型 HTTP 服务器 (把刚刚固定的 base_dir 传给它)
            self.start_local_http_server(base_dir)
            
            # 5. 使用 127.0.0.1 打开
            import webbrowser
            target_url = f"http://127.0.0.1:{HTTP_SERVER_PORT}/{html_filename}"
            webbrowser.open(target_url)
            
            message = f"并查集提取完毕，共 {G.number_of_nodes()} 个节点，{edges_found} 条边。\n浏览器即将打开：{target_url}"
            return message
            
        