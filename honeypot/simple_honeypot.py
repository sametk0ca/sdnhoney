import asyncio
import logging
import datetime
import os

# Log dizini ve dosyasını ayarla
LOG_DIR = "/home/samet/capstone/logs"
LOG_FILE = os.path.join(LOG_DIR, "simple_honeypot.log")

# Loglama ayarları: Hem dosyaya hem konsola yaz
logger = logging.getLogger()
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Dosya handler’ı
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Konsol handler’ı
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

class SimpleHoneypot:
    def __init__(self, host='0.0.0.0', port=80):  # Port 80 olarak ayarlı
        self.host = host
        self.port = port
        logging.info("Honeypot başlatılıyor...")

    async def handle_client(self, reader, writer):
        client_addr = writer.get_extra_info('peername')
        client_ip, client_port = client_addr[0], client_addr[1]
        logging.info(f"Bağlantı alındı: {client_ip}:{client_port}")

        try:
            data = await reader.read(1024)
            if data:
                message = data.decode(errors='ignore')
                logging.info(f"Veri alındı: {client_ip}:{client_port} - {message.strip()}")
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Length: 12\r\n"
                    "\r\n"
                    "Hello, World!\n"
                )
                writer.write(response.encode())
                await writer.drain()

        except Exception as e:
            logging.error(f"Hata: {client_ip}:{client_port} - {str(e)}")
        
        finally:
            writer.close()
            await writer.wait_closed()
            logging.info(f"Bağlantı kapatıldı: {client_ip}:{client_port}")

    async def start_server(self):
        server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )
        addr = server.sockets[0].getsockname()
        logging.info(f"Honeypot başlatıldı: {addr}")
        async with server:
            await server.serve_forever()

    def run(self):
        asyncio.run(self.start_server())

if __name__ == "__main__":
    honeypot = SimpleHoneypot(host='0.0.0.0', port=80)
    honeypot.run()