import socket
import json
import os
import sys
import subprocess
import time
import csv                  # 新增
from config import HOST, PORT

# --- 全局状态 ---
GLOBAL_PROCESS = None
EXE_PATH = None


def get_exe_path():
    """计算 exe 的绝对路径 (兼容 PyInstaller 打包)"""
    global EXE_PATH
    if getattr(sys, 'frozen', False):
        # 如果是被 PyInstaller 打包后的运行环境
        # sys._MEIPASS 指向打包后程序所在的根目录
        base_dir = sys._MEIPASS
        EXE_PATH = os.path.join(base_dir, "build", "main.exe")
    else:
        # 正常的本地开发环境
        current_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(current_dir)
        EXE_PATH = os.path.join(parent_dir, "build", "main.exe")

def convert_pcap_to_csv(pcap_path):
    """读取 pcap/pcapng 文件并生成供 C 语言读取的临时 csv 文件"""
    import sys
    import os
    import dpkt
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 获取正确的父级目录（兼容打包环境的临时解压目录 _MEIPASS）
    if getattr(sys, 'frozen', False):
        parent_dir = sys._MEIPASS
    else:
        parent_dir = os.path.dirname(current_dir)
        
    data_dir = os.path.join(parent_dir, "data")
    # 【核心修复 1】强制创建 data 文件夹，exist_ok=True 表示如果已存在就不报错
    os.makedirs(data_dir, exist_ok=True) 
    
    file_name_only = os.path.splitext(os.path.basename(pcap_path))[0] + ".csv"
    csv_path = os.path.join(data_dir, file_name_only)

    with open(pcap_path, 'rb') as pcap_file, open(csv_path, mode='w', newline='', encoding='utf-8') as csv_out:
        writer = csv.writer(csv_out)
        # 先写一行表头，因为在读的时候是会跳过第一行表头的
        writer.writerow(["Source", "Destination", "Protocol", "SrcPort", "DstPort", "DataSize", "Duration"])

        # 尝试按照 pcap 格式读取，兼容大部分情况
        try:
            pcap = dpkt.pcap.Reader(pcap_file)
        except ValueError:
            # 如果报错，说明可能是 pcapng 格式
            pcap_file.seek(0)
            pcap = dpkt.pcapng.Reader(pcap_file)

        for timestamp, buf in pcap:
            try:
                # 解析以太网层
                eth = dpkt.ethernet.Ethernet(buf)
                
                # 只处理 IP 数据包 (IPv4)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                
                ip = eth.data
                
                # 将二进制 IP 转换成字符串 (如 "192.168.1.1")
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                data_size = len(buf) # 整个数据包大小
                
                protocol, src_port, dst_port = 0, 0, 0
                if isinstance(ip.data, dpkt.tcp.TCP):
                    protocol, src_port, dst_port = 6, ip.data.sport, ip.data.dport
                elif isinstance(ip.data, dpkt.udp.UDP):
                    protocol, src_port, dst_port = 17, ip.data.sport, ip.data.dport
                elif isinstance(ip.data, dpkt.icmp.ICMP):
                    protocol = 1
                
                # 假设持续时间为 0.0，如果你 C 里面不需要这个字段可以写 0
                duration = 0.0 
                writer.writerow([src_ip, dst_ip, protocol, src_port, dst_port, data_size, duration])
                
            except Exception:
                # 忽略个别损坏或无法解析的包，继续下一个
                continue

    print(f"[Daemon] 转换完成，已生成临时 CSV: {csv_path}")
    return csv_path

def send_command(payload):
    # 这个函数负责传送给C指令，并且解析具体的参数，指令
    print(f"解析指令: {payload}")

    mode = payload.get("mode")
    print(f"排序模式: {mode}")
    key = payload.get("key")
    print(f"根据{key}进行排序")
    change = payload.get("change")
    print(f"更改的是{change}变量")

    if change == 'mode':
        GLOBAL_PROCESS.stdin.write('M'+str(mode)+'\n') # 给C传输mode选项参数
        GLOBAL_PROCESS.stdin.flush()
    elif change == 'key':
        GLOBAL_PROCESS.stdin.write('K'+str(key)+'\n') # 给C传输mode选项参数
        GLOBAL_PROCESS.stdin.flush()
    else:
        print(f"解析指令失败: “change”变量为{change}")

def read_until_prompt(process, timeout=5):
    """持续读取 C 程序的输出，直到遇到等待输入的提示词"""
    output_lines = [] # 创建新列表
    print("--- [Daemon] 开始读取 C 程序输出 ---") # 调试时可打开
    while True:
        # 检查进程是否挂了
        if process.poll() is not None:
            print("[Daemon] C 进程已退出！")
            rest = process.stdout.read()
            if rest:
                print(f"[Daemon] 进程遗言: {rest}")
                output_lines.append(rest)
            break

        # 读取一行
        try:
            # 使用 readline 读取，如果 encoding 不对，这里可能会由 UnicodeDecodeError
            line = process.stdout.readline()
        except Exception as e:
            print(f"[Daemon] 读取/解码错误: {e}")
            break

        if not line:
            time.sleep(0.01)
            continue
            
        clean_line = line.strip()
        # >>> 关键调试信息：打印收到的每一行 <<<
        print(f"[C Output] {clean_line}") 

        # 判断是否结束
        if "Waiting" in clean_line:
            print("--- 检测到等待输入提示符，读取结束 ---")
            break

        if ',' in clean_line:
            if clean_line.endswith(','):
                # 针对你的扩展功能：如果是逗号结尾，去掉尾部逗号，保留为【纯文本字符串】
                output_lines.append(clean_line[:-1])
            else:
                # 针对首页表格数据：如果不以逗号结尾，切分成【列表】
                output_lines.append(clean_line.split(','))
            
    return output_lines

# 所有信息确实都要途径daemon，还有后端的错误信息也是。
# 想要妥善处理报错的话，就是要把报错信息分类。主窗口的话，C错误返给daemon，daemon传给前端报错具体内容。所以还是要用response传的，因为要提取错误信息。
# 那就是一个是status，一个是data，一个是message。先检查status，然后如果出错了的话看message
def handle_client(conn, addr):
    global GLOBAL_PROCESS
    response = {}
    
    print(f"开始处理gui的新请求，gui端口: {addr}")
    try:
        conn.settimeout(5.0)
        raw_request = conn.recv(4096) # 接收传输
        if not raw_request: # 客户端已经正常关闭了连接
            print("[Server] 客户端断开连接 (无数据)。")
            return
        
        request = json.loads(raw_request.decode('utf-8')) # 从gui返回一个Python字典
        command = request.get("command") # 从字典里面读取command
        payload = request.get("payload", {})  # 从字典里面读取payload
        print(f"[Server] 执行指令: {command}")
        # ---------------------------------------------------------
        # 动作 1: 加载文件 (初始化/重启 C 进程)
        # ---------------------------------------------------------
        if command == "LOAD_FILE":
            # 从 payload 字典中读取 file_path
            file_path = payload.get("file_path") # 这个是要加载的文件的path
            
            # 如果是 pcap 文件，先转换成 csv
            if file_path.lower().endswith(('.pcap', '.pcapng')):
                try:
                    # 把转换后的 csv 路径覆盖原本的 file_path，假装用户传的就是这个 csv
                    file_path = convert_pcap_to_csv(file_path)
                except Exception as e:
                    response = {"status": "error", "message": f"PCAP 解析失败: {str(e)}"}
                    return
            
            if GLOBAL_PROCESS is None or GLOBAL_PROCESS.poll() is not None:
                # 进程不存在或已挂掉，必须启动
                print("[Server] 进程未运行，准备启动新进程。")
            else:
                # 因为功能是LOAD_FILE，所以一定要重启进程，清空状态
                print("[Server] 检测到新文件加载请求，将重启进程。")
                # 杀掉旧进程
                GLOBAL_PROCESS.kill()
                GLOBAL_PROCESS.wait()
                GLOBAL_PROCESS = None

            if not os.path.exists(EXE_PATH):
                response = {"status": "error", "message": f"找不到EXE: {EXE_PATH}"}
            else:
                try:
                    print(f"启动新进程: {EXE_PATH} {file_path}")
                    import subprocess

                    if getattr(sys, 'frozen', False):
                        c_creationflags = subprocess.CREATE_NO_WINDOW
                    else:
                        c_creationflags = 0 # 源码环境正常运行

                    # 启动 C 进程，注意 encoding='gbk' 适应 Windows 中文环境
                    GLOBAL_PROCESS = subprocess.Popen(
                        [EXE_PATH, file_path],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        bufsize=1, # 行缓冲
                        encoding='gbk' ,
                        creationflags=c_creationflags
                    )
                    
                    # 读取启动后的初始化输出（直到出现提示符[Waiting...]）
                    init_output = read_until_prompt(GLOBAL_PROCESS, timeout=10)
                    full_text = "\n".join(init_output) # 给输出加一个回车？
                    
                    # 打印到控制台，方便你直接看黑框框
                    # print(f"--- C程序启动输出 ---\n{full_text}\n-----------------------")

                    if "Error" in full_text or GLOBAL_PROCESS.poll() is not None:
                        # 关键修改：把 full_text (C的具体输出) 放到 message 里，让弹窗显示出来
                        err_msg = f"C程序启动失败。\n\nC程序输出内容:\n{full_text}"
                        response = {"status": "error", "message": err_msg}
                        GLOBAL_PROCESS = None # 标记为无进程
                    else:
                        response = {"status": "success", "message": "文件已经加载到C，初始化构建已完成，等待指令", "output": full_text}
                        
                except Exception as e:
                    response = {"status": "error", "message": str(e)}
                    GLOBAL_PROCESS = None
            # 发送回执
            # conn.sendall(json.dumps(response).encode('utf-8'))

        # ==========================================
        # 新增动作: 停止 C 进程 (由 home.py 的重新选择按钮调用)
        # ==========================================
        elif command == "STOP_PROCESS":
            print("[Server] 收到重新选择文件请求，正在清理旧的 C 进程...")
            if GLOBAL_PROCESS is not None: 
                try:
                    GLOBAL_PROCESS.kill()
                    GLOBAL_PROCESS.wait()  # 等待进程彻底死亡，回收资源
                    print("[Server] C 进程已成功结束。")
                except Exception as e:
                    print(f"[Server] 结束 C 进程时出错: {e}")
                finally:
                    GLOBAL_PROCESS = None
            else:
                print("[Server] 当前没有运行的 C 进程，无需清理。")
            
            # 返回成功回执
            response = {"status": "success", "message": "后台进程已清理"}

        # ---------------------------------------------------------
        # 动作 2: 发送指令 (由 home.py 调用)
        # ---------------------------------------------------------
        elif command == "APPLY_SORT":
            if GLOBAL_PROCESS and GLOBAL_PROCESS.poll() is not None: raise Exception("后台进程未运行，请先在首页加载文件")
            
            send_command(payload)

            # 2. 读取结果，直到下一次出现提示词
            cmd_output = read_until_prompt(GLOBAL_PROCESS, timeout=15)

            response = {
                "status": "success", 
                "data": cmd_output, # 返回的是一个列表，包含每一行
            }
        
        # ---------------------------------------------------------
        # 动作 6: 叠加条件筛选 (由 home.py 的 apply_settings 调用)
        # ---------------------------------------------------------
        elif command == "APPLY_ADVANCED_FILTER":
            if GLOBAL_PROCESS and GLOBAL_PROCESS.poll() is not None: raise Exception("后台进程未运行，请先在首页加载文件")
            
            payload = request.get("payload", {})
            
            # 获取值，如果为空则赋予默认值 "-" 或 "-1"
            any_ip = payload.get("any_ip", "").strip() or "-"
            src_ip = payload.get("src_ip", "").strip() or "-"
            dst_ip = payload.get("dst_ip", "").strip() or "-"
            src_port = payload.get("src_port", -1)
            dst_port = payload.get("dst_port", -1)
            
            # 布尔值转为 1 或 0
            tcp = 1 if payload.get("tcp") else 0
            udp = 1 if payload.get("udp") else 0
            icmp = 1 if payload.get("icmp") else 0
            other = 1 if payload.get("other") else 0
            
            # 拼接成给 C 的指令，例如 "F 192.168.1.1 - 443 -1 1 0 0\n"
            cmd_str = f"F {any_ip} {src_ip} {dst_ip} {src_port} {dst_port} {tcp} {udp} {icmp} {other}\n"
            
            GLOBAL_PROCESS.stdin.write(cmd_str)
            GLOBAL_PROCESS.stdin.flush()
            
            cmd_output = read_until_prompt(GLOBAL_PROCESS, timeout=15)
            response = {
                "status": "success", 
                "data": cmd_output, # 返回的是一个列表，包含每一行
            }

        # ---------------------------------------------------------
        # 动作 3: ratio (由 home.py 调用)
        # ---------------------------------------------------------
        elif command == "APPLY_RATIO_FILTER":
            if GLOBAL_PROCESS and GLOBAL_PROCESS.poll() is not None: raise Exception("后台进程未运行，请先在首页加载文件")
            
            threshold = request.get("payload", {}).get("threshold", 0.0)
            # 把数字拼成字符串，比如 "R0.8\n"，送给 C 进程的 stdin
            cmd_str = f"R{threshold}\n"
            GLOBAL_PROCESS.stdin.write(cmd_str)
            GLOBAL_PROCESS.stdin.flush()
            
            cmd_output = read_until_prompt(GLOBAL_PROCESS, timeout=15)
            
            # 原样返回给 GUI 刷新界面
            response = {
                "status": "success", 
                "data": cmd_output
            }

        # ---------------------------------------------------------
        # 动作 4: 处理关闭服务器指令 (由 home.py 退出时调用)
        # ---------------------------------------------------------
        elif command == "SHUTDOWN":
            print("[Server] 收到前端的 SHUTDOWN 指令，准备安全退出...")
            
            # 1. 杀掉正在运行的 C 引擎进程
            if GLOBAL_PROCESS and GLOBAL_PROCESS.poll() is None:
                print("[Server] 正在杀死残存的 C 引擎进程...")
                GLOBAL_PROCESS.kill()
                GLOBAL_PROCESS.wait()
            
            # 2. 给前端回执
            response = {"status": "success", "message": "Server shutting down"}
            
            # 3. 强制退出当前的 Daemon 进程
            # 使用 os._exit(0) 可以无视多线程的阻塞（比如 server.accept()），直接干净利落地干掉后台黑框
            os._exit(0)
        
        # ---------------------------------------------------------
        # 新增动作: 路径查找 (由 path_find_window.py 调用)
        # ---------------------------------------------------------
        elif command == "FIND_PATH":
            if GLOBAL_PROCESS and GLOBAL_PROCESS.poll() is not None: raise Exception("后台进程未运行，请先在首页加载文件")
            
            payload = request.get("payload", {})
            src_ip = payload.get("src_ip", "")
            dst_ip = payload.get("dst_ip", "")
            
            # 拼接给 C 语言的指令，例如 "P 192.168.1.1 10.0.0.1\n"
            cmd_str = f"P {src_ip} {dst_ip}\n"
            print(f"[Server] 发送路径查找指令给 C: {cmd_str.strip()}")
            
            GLOBAL_PROCESS.stdin.write(cmd_str)
            GLOBAL_PROCESS.stdin.flush()
            
            # 读取 C 程序的返回，直到出现 [Waiting...]
            cmd_output = read_until_prompt(GLOBAL_PROCESS, timeout=15)
            
            # 组装成功的数据回传给 GUI
            response = {
                "status": "success",
                "data": cmd_output # 去掉最后那句 Waiting 提示
            }
            
        # ---------------------------------------------------------
        # 动作 5:  星状结构检测 (由 star_structure_window.py 调用)
        # ---------------------------------------------------------
        elif command == "FIND_STAR":
            if GLOBAL_PROCESS and GLOBAL_PROCESS.poll() is not None: raise Exception("后台进程未运行，请先在首页加载文件")
            
            threshold = request.get("payload", {}).get("threshold", 20)
            print(f"[Server] 发送星状结构检测指令给 C: S{threshold}")

            # S 代表 Star Structure (Extension method)
            GLOBAL_PROCESS.stdin.write(f"S{threshold}\n")
            GLOBAL_PROCESS.stdin.flush()
            
            # 读取 C 程序的返回，直到出现 [Waiting...]
            cmd_output = read_until_prompt(GLOBAL_PROCESS, timeout=15)
            
            response = {
                "status": "success",
                "data": cmd_output # 截去末尾的 Waiting...
            }

        # ---------------------------------------------------------
        # 新增动作: 安全规则检测
        # ---------------------------------------------------------
        elif command == "CHECK_SECURITY":
            if GLOBAL_PROCESS and GLOBAL_PROCESS.poll() is not None: raise Exception("后台进程未运行，请先在首页加载文件")
                
            payload = request.get("payload", {})
            ip1 = payload.get("ip1", "")
            ip2 = payload.get("ip2", "")
            ip3 = payload.get("ip3", "")
            action = payload.get("action", 0)
            
            # 拼接指令: C + ip1,ip2,ip3,action\n
            cmd_str = f"C {ip1} {ip2} {ip3} {action}\n"
            print(f"[Server] 发送安全检测指令给 C: {cmd_str}")
            
            GLOBAL_PROCESS.stdin.write(cmd_str)
            GLOBAL_PROCESS.stdin.flush()
            
            cmd_output = read_until_prompt(GLOBAL_PROCESS, timeout=10)
            response = {"status": "success", "data": cmd_output}
             
        # ---------------------------------------------------------
        # 新增动作: 子图可视化 (并查集提取)
        # ---------------------------------------------------------
        elif command == "VISUALIZE_GRAPH":
            
            if GLOBAL_PROCESS and GLOBAL_PROCESS.poll() is not None: raise Exception("后台进程未运行，请先在首页加载文件")
                
            target_ip = request.get("payload", {}).get("target_ip", "")
            
            # 指令 V + IP
            cmd_str = f"V{target_ip}\n"
            
            GLOBAL_PROCESS.stdin.write(cmd_str)
            GLOBAL_PROCESS.stdin.flush()
            cmd_output = read_until_prompt(GLOBAL_PROCESS, timeout=10)
            response = {"status": "success", "data": cmd_output}
        
        else:
            response = {"status": "error", "message": "未知指令"}

    except Exception as e:
        print(f"Server Error: {e}")
        response = {"status": "error", "message": str(e)}
    finally:
        # 发送回执
        conn.sendall(json.dumps(response).encode('utf-8'))
        print("server完成一轮指令，已经向gui反馈")
        conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # 启动一个server socket
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((HOST, PORT))
        server.listen(5) 
        print(f"Daemon Server (单线程持久化版) 正在监听 {HOST}:{PORT} ...")
        print("请勿关闭此窗口。")
        
        while True:
            conn, addr = server.accept() # 持续监听，有新的就创建一个线程
            print(f"\n[Server] 收到新的请求，gui端口: {addr}")
            try:
                handle_client(conn, addr)
            except Exception as e:
                print(f"[Server] 处理gui请求时崩溃: {e}")
            
    except KeyboardInterrupt:
        print("\n[Server] 接收到停止信号...")
    except Exception as e:
        print(f"启动失败: {e}")
    finally:
        # 清理资源
        if GLOBAL_PROCESS:
            print("[Server] 正在关闭 C 进程...")
            GLOBAL_PROCESS.kill()
            GLOBAL_PROCESS.wait()
        server.close()
        print("[Server] 服务器已关闭。")

class DaemonConnection:

    def __init__(self):
        self.server_running = False
        self.connect = False # 这里指的是谁和谁的connect？
        self.response = {}
        self.data = []

        self.test_daemon()
        if not self.server_running:
            try:
                self.start_daemon()
            except:
                raise Exception("错误", f"无法启动后台服务")

    def test_daemon(self):
        self.server_running = False
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = test_sock.connect_ex((HOST, PORT))
        test_sock.close()  # 先关闭 Socket，再进行判断和 return
        
        if result == 0: # 说明端口是通的，设置标志位
            self.server_running = True
            return True
        else:
            return False
    
    def start_daemon(self):
        # 端口没开，说明 daemon 没运行，启动它
        print("正在启动 daemon_server.py ...")
        if getattr(sys, 'frozen', False):
            # 打包环境下：调用 exe 自己，并传入暗号 "run_daemon"
            subprocess.Popen([sys.executable, "run_daemon"], 
                             creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            # 源码运行环境：保持原样
            current_dir = os.path.dirname(os.path.abspath(__file__))
            daemon_path = os.path.join(current_dir, "daemon_server.py")
            subprocess.Popen([sys.executable, daemon_path], 
                             creationflags=subprocess.CREATE_NEW_CONSOLE)
        print("已启动 daemon_server.py")
        self.server_running = True

    def shut_daemon(self):
        print("检测到窗口关闭，正在清理资源...")
        
        # 1. 停止可能存在的本地循环/线程标志位（如果有的话）
        self.server_running = False
        
        # 2. 建立一个临时的一次性 Socket，通知 Daemon Server 退出
        try:
            shutdown_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            shutdown_sock.settimeout(1.0) # 设置较短的超时时间，防止卡死
            shutdown_sock.connect((HOST, PORT)) # 使用你文件顶部的 HOST 和 PORT
            
            request = {
                "command": "SHUTDOWN",
                "payload": {}
            }

            shutdown_sock.sendall(json.dumps(request).encode('utf-8'))
            shutdown_sock.close()
            print("已成功向 Daemon 发送关闭指令")
        except ConnectionRefusedError:
            print("后台 Daemon 似乎已经关闭，无需重复发送。")
        except Exception as e:
            print(f"尝试通知 Daemon 关闭时发生异常: {e}")

    def connect_daemon_mul(self):
        #尝试连接 Daemon (带重试机制) 
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected = False

        import time
        times = 10
        for i in range(times): # 尝试 10 次
            try:
                self.client_socket.connect((HOST, PORT))
                self.connected = True
                print(f"成功连接到后台服务 (尝试次数: {i+1})")
                break
            except ConnectionRefusedError:
                print(f"等待后台服务启动... ({i+1}/{times})")
                time.sleep(0.5) # 等待 0.5 秒再试
            except Exception as e:
                print(f"连接发生其他错误: {e}")
                times = 3
                time.sleep(0.5)

        if not self.connected:
            raise Exception("错误", f"无法连接到后台服务。daemon_server运行状态为{self.server_running}")

    def connect_daemon(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected = False
        try:
            self.client_socket.settimeout(2.0)
            self.client_socket.connect((HOST, PORT)) # 连接上监听端口
            return self.client_socket
        except:
            raise Exception("daemon_connection mistake")

    def send_daemon(self, request):
        # 发送指令
        try:
            self.client_socket.sendall(json.dumps(request).encode('utf-8')) # send
            print(f"已发送request{request}, 等待daemon响应...")
        except:
            raise Exception("错误", f"无法向daemon_server发送信息。daemon_server运行状态为{self.server_running}，连接状态为{self.connected}")

    def recv_daemon(self, timeout=10):
        # 下面是接收，如果没有收到上面的exception，那么就是接收出了问题
        self.client_socket.settimeout(timeout)
        buffer = bytearray() # 内置类型，可变字节串
        while True:
            chunk = self.client_socket.recv(8192) 
            if not chunk: break
            buffer.extend(chunk) # 把接到的水倒进大缸(buffer)里
            if b'__END__' in buffer: break # 看到结束标志了，说明数据传完了，跳出循环

        raw_result = buffer.split(b'__END__')[0]
        if not raw_result: raise Exception("未收到数据")

        print(f"✅ 成功接收完整数据，总大小: {len(raw_result)} 字节")
        result = json.loads(raw_result.decode('utf-8')) # 解码
        print(f"解码后的数据类型: {type(result)}")
        print(f"解码后数据总大小: {len(result)} 字节")

        return result
    
    def cut_daemon_connection(self):
        self.client_socket.close()

if __name__ == "__main__":
    get_exe_path()
    start_server()