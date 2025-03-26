import asyncio
from h2.config import H2Configuration
from h2.connection import H2Connection
import httpx
from h2.events import RequestReceived

class H2ProxyServer:
    def __init__(self, host, port, target_host):
        self.host = host
        self.port = port
        self.target_host = target_host
        self.config = H2Configuration(client_side=False)
        self.connections = {}

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
                        await self.process_request(event, conn, writer)
                writer.write(conn.data_to_send())
                await writer.drain()
        finally:
            del self.connections[writer]
            writer.close()
            await writer.wait_closed()

    async def process_request(self, event, conn, writer):
        headers = {name: value for name, value in event.headers}
        ip_source = writer.get_extra_info('peername')[0]
        print("Request from ", ip_source)
        if ip_source != self.target_host:
            with httpx.Client(http1=False,http2=True, verify=False) as client:
                target_url = f'http://{self.target_host}:8000{headers[b":path"].decode()}'
                headers = {b"authorization": headers[b"authorization"]}
                response = client.get(target_url, headers=headers)
                response_headers = [(k, v) for k, v in response.headers.items()]
                if ":status" not in headers : 
                    response_headers = [(":status",str(response.status_code))] + response_headers
                conn.send_headers(event.stream_id, response_headers, end_stream=False)
                conn.send_data(event.stream_id, response.content, end_stream=True)
        else:
            conn.send_headers(event.stream_id, [(':status', '200')], end_stream=False)
            conn.send_data(event.stream_id, b'Request initiated by udm', end_stream=True)

    async def run(self):
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        async with server:
            await server.serve_forever()

if __name__ == '__main__':
    proxy = H2ProxyServer(host='0.0.0.0', port=8000, target_host='10.100.200.9')
    asyncio.run(proxy.run())
