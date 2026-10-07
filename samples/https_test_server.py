import http.server
import ssl


HOST = "127.0.0.1"
PORT = 8443

CERT_FILE = "samples\server.crt"
KEY_FILE = "samples\server.key"


class HTTPSRequestHandler(
    http.server.SimpleHTTPRequestHandler
):
    pass


server = http.server.HTTPServer(
    (HOST, PORT),
    HTTPSRequestHandler,
)


context = ssl.SSLContext(
    ssl.PROTOCOL_TLS_SERVER
)

context.load_cert_chain(
    certfile=CERT_FILE,
    keyfile=KEY_FILE,
)

server.socket = context.wrap_socket(
    server.socket,
    server_side=True,
)

print(
    f"HTTPS test server running at "
    f"https://{HOST}:{PORT}"
)

server.serve_forever()