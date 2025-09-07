import socket
import threading
import logging
import struct
import select

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger('FullSOCKS5Proxy')

class FullSocks5Proxy:
    def __init__(self):
        self.running = True
    
    def parse_socks5_request(self, data):
        """解析SOCKS5请求"""
        if len(data) < 10:
            return None
            
        version = data[0]
        cmd = data[1]
        rsv = data[2]
        atype = data[3]
        
        # 解析地址
        if atype == 1:  # IPv4
            if len(data) < 10:
                return None
            target_ip = socket.inet_ntoa(data[4:8])
            target_port = struct.unpack('!H', data[8:10])[0]
            return (target_ip, target_port), 10
            
        elif atype == 3:  # 域名
            domain_length = data[4]
            if len(data) < 5 + domain_length + 2:
                return None
            domain = data[5:5+domain_length].decode('ascii')
            target_port = struct.unpack('!H', data[5+domain_length:7+domain_length])[0]
            return (domain, target_port), 7 + domain_length
            
        elif atype == 4:  # IPv6
            if len(data) < 22:
                return None
            target_ip = socket.inet_ntop(socket.AF_INET6, data[4:20])
            target_port = struct.unpack('!H', data[20:22])[0]
            return (target_ip, target_port), 22
            
        return None
    
    def forward_data(self, client_sock, target_sock):
        """双向数据转发"""
        try:
            while self.running:
                # 使用select监控socket
                readable, _, _ = select.select([client_sock, target_sock], [], [], 60)
                
                for sock in readable:
                    try:
                        data = sock.recv(4096)
                        if not data:
                            return
                            
                        if sock is client_sock:
                            # 客户端 -> 目标服务器
                            target_sock.sendall(data)
                            logger.info(f"📤 发送到目标: {len(data)}字节")
                        else:
                            # 目标服务器 -> 客户端
                            client_sock.sendall(data)
                            logger.info(f"📥 发送到客户端: {len(data)}字节")
                            
                    except (socket.error, OSError):
                        return
                        
        except Exception as e:
            logger.error(f"数据转发错误: {e}")
        finally:
            client_sock.close()
            target_sock.close()
    
    def handle_client(self, client_socket, addr):
        """处理客户端连接"""
        target_socket = None
        
        try:
            logger.info(f"📞 新连接: {addr}")
            
            # 1. SOCKS5握手
            handshake = client_socket.recv(4096)
            if not handshake or len(handshake) < 3:
                return
                
            logger.info(f"握手: {handshake.hex()}")
            
            # 响应握手
            response = bytes([0x05, 0x00])  # SOCKS5, 无认证
            client_socket.send(response)
            logger.info("✅ 握手完成")
            
            # 2. 读取SOCKS5请求
            request_data = client_socket.recv(4096)
            if not request_data:
                return
                
            logger.info(f"请求: {request_data.hex()}")
            
            # 解析请求
            result = self.parse_socks5_request(request_data)
            if not result:
                logger.error("❌ 解析请求失败")
                return
                
            target_addr, bytes_used = result
            logger.info(f"目标地址: {target_addr}")
            
            # 3. 连接到真实的目标服务器
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.settimeout(30)
            target_socket.connect(target_addr)
            logger.info(f"✅ 连接到目标: {target_addr}")
            
            # 4. 发送成功响应
            response = bytes([0x05, 0x00, 0x00, 0x01])  # 成功
            response += socket.inet_aton('0.0.0.0')  # 绑定地址
            response += struct.pack('!H', 1000)  # 绑定端口
            client_socket.send(response)
            logger.info("✅ 发送成功响应")
            
            # 5. 开始数据转发
            logger.info("🔄 开始数据转发...")
            self.forward_data(client_socket, target_socket)
            logger.info("✅ 数据转发完成")
            
        except Exception as e:
            logger.error(f"处理错误: {e}")
            # 发送失败响应
            try:
                if client_socket.fileno() != -1:
                    response = bytes([0x05, 0x05, 0x00, 0x01])  # 连接拒绝
                    response += socket.inet_aton('0.0.0.0')
                    response += struct.pack('!H', 0)
                    client_socket.send(response)
            except:
                pass
        finally:
            if target_socket:
                target_socket.close()
            client_socket.close()
            logger.info(f"📴 关闭连接: {addr}")
    
    def start_server(self, host='127.1.1.1', port=1000):
        """启动完整的SOCKS5代理服务器"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind((host, port))
            server.listen(5)
            logger.info(f"🚀 完整SOCKS5代理启动在 {host}:{port}")
            logger.info("📍 等待QQ连接...")
            
            while self.running:
                client_socket, addr = server.accept()
                thread = threading.Thread(target=self.handle_client, args=(client_socket, addr))
                thread.daemon = True
                thread.start()
                
        except Exception as e:
            logger.error(f"服务器错误: {e}")
        finally:
            server.close()

if __name__ == '__main__':
    # 启动完整版SOCKS5代理
    proxy = FullSocks5Proxy()
    proxy.start_server('127.1.1.1', 1000)