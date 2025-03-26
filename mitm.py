import asyncio
from h2.config import H2Configuration
from h2.connection import H2Connection
import httpx
from h2.events import *
import json

class H2ProxyServer:
    def __init__(self, host, port, target_host, display=False):
        self.host = host
        self.port = port
        self.target_host = target_host
        self.config = H2Configuration(client_side=False)
        self.connections = {}
        self.buffers = {}
        self.display = display

    async def handle_client(self, reader, writer):
        conn = H2Connection(config=self.config)
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        await writer.drain()

        self.connections[writer] = conn

        try:
            while True:
                data = await reader.read(65535)
                if not data:
                    break
                events = conn.receive_data(data)
                for event in events:
                    if isinstance(event, RequestReceived):
                        self.buffers[event.stream_id] = {
                            'headers': event.headers,
                            'data': b""
                        }
                    elif isinstance(event, DataReceived):
                        # Ajouter les données reçues au tampon correspondant
                        self.buffers[event.stream_id]['data'] += event.data
                    elif isinstance(event, StreamEnded):
                        # Traiter la requête complète
                        await self.process_request(event.stream_id, conn, writer)
                writer.write(conn.data_to_send())
                await writer.drain()
        finally:
            del self.connections[writer]
            writer.close()
            await writer.wait_closed()

    async def process_request(self, stream_id, conn, writer):
        headers = self.buffers[stream_id]['headers']
        body = self.buffers[stream_id]['data']
        del self.buffers[stream_id]  # Nettoyer le tampon
        headers = {name.decode('utf-8'): value.decode('utf-8') for name, value in headers}

        ip_source = writer.get_extra_info('peername')[0]
        if ip_source != self.target_host:
            
            body = self.buffers.pop(stream_id, b"")  # Obtenir et supprimer le tampon
            with httpx.Client(http1=False,http2=True, verify=False) as client:
                target_url = f'http://{self.target_host}:8000{headers[":path"]}'
                method = headers[":method"]
                headers = {"authorization": headers["authorization"]}
                
                data = {}
                if body:
                    try:
                        data = json.loads(body.decode('utf-8'))
                        if self.display : 
                            print(f"Data received {data}")
                    
                    except json.JSONDecodeError:
                        print("Invalid JSON", body.decode('utf-8'))
                
                if method in ["GET", "DELETE"]:
                    response = client.request(method, target_url, headers=headers)
                else:
                    response = client.request(method, target_url, json=data, headers=headers)
                
                response_headers = [(k, v) for k, v in response.headers.items()]
                if ":status" not in headers : 
                    response_headers = [(":status",str(response.status_code))] + response_headers
                    
                conn.send_headers(stream_id, response_headers, end_stream=False)
                conn.send_data(stream_id, response.content, end_stream=True)
                if self.display : 
                    print(f"Forwarded {target_url} from {ip_source} to {self.target_host}")
        
        else: 
            print(f"Warning : Request from spoofed NF {self.target_host}")

    async def run(self):
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        async with server:
            await server.serve_forever()

if __name__ == '__main__':
    proxy = H2ProxyServer(host='0.0.0.0', port=8000, target_host='10.100.200.10', display=True)
    asyncio.run(proxy.run())
