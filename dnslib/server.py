import socket
from .response import DNSResponse

class DNSResolver:
	def __init__(self, port=53):
		self.ipport = ("127.0.0.1", port)
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	def run(self):
		sock = self.sock
		sock.bind(self.ipport)
		print("[i] DNS Initialized")
		while True:
			# Retrieve 512 bytes of data based on the RFC-1035 (2.3.5. Size Limits)
			data, address = sock.recvfrom(512)
			response = DNSResponse(data)
			print(f"[i] Sending tx {int.from_bytes(response.txid, byteorder='big')} to {address}")
			sock.sendto(response.bytes(), address)
