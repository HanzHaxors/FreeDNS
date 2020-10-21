import socket, glob, json
import dns.resolver

resolver = dns.resolver.Resolver()
resolver.nameservers = ["1.1.1.1"]

packet = dict()
packet["1"] = "a"
packet["28"] = "aaaa"
packet["18"] = "afsdb"
packet["42"] = "apl"
packet["257"] = "caa"
packet["60"] = "cdnskey"
packet["59"] = "xds"
packet["37"] = "cert"
packet["5"] = "cname"
packet["62"] = "csync"
packet["49"] = "dhcid"
packet["32769"] = "dlv"
packet["39"] = "dname"
packet["48"] = "dnskey"
packet["43"] = "ds"
packet["108"] = "eui48"
packet["13"] = "hinfo"
packet["55"] = "hip"
packet["45"] = "ipseckey"
packet["25"] = "key"
packet["36"] = "kx"
packet["29"] = "loc"
packet["15"] = "mx"
packet["35"] = "naptr"
packet["2"] = "ns"
packet["47"] = "nsec"
packet["50"] = "nsec3"
packet["51"] = "nsec3param"
packet["61"] = "openpgpkey"
packet["12"] = "ptr"
packet["46"] = "rrsig"
packet["17"] = "rp"
packet["24"] = "sig"
packet["53"] = "smimea"
packet["6"] = "soa"
packet["33"] = "srv"
packet["44"] = "sshfp"
packet["32768"] = "ta"
packet["249"] = "tkey"
packet["52"] = "tlsa"
packet["250"] = "tsig"
packet["16"] = "txt"
packet["256"] = "uri"
packet["63"] = "zonemd"
packet["64"] = "svcb"
packet["65"] = "https"

class DNSResponse:
	def __init__(self, data):
		"""
		Initialize object values
		"""
		txid = data[:2] # Get bytes 0 to 2
		flags = ''

		self.zones = self.loadzones()

		# Parse flags
		flags = self.parseFlags(data[2:4])

		# Questions
		QDCOUNT = b"\x00\x01"

		# Answer Count
		ANCOUNT = len(self.getreq(data[12:])[0]).to_bytes(2, byteorder="big")

		# Nameserver Count
		NSCOUNT = (0).to_bytes(2, byteorder="big")

		# Additional Count
		ARCOUNT = (0).to_bytes(2, byteorder="big")

		dnsheader = txid + flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

		# Create DNS Body
		dnsbody = b''

		# Get answer for query
		records, rectype, domainname = self.getreq(data[12:])

		dnsquestion = self.buildquestion(domainname, rectype)

		for record in records:
			dnsbody += self.rectobytes(domainname, rectype,
								  record["ttl"], record["value"])

		self.txid = txid
		self.flags = flags
		self.domain = domainname
		self.record = rectype
		self.dnsheader = dnsheader
		self.dnsquestion = dnsquestion
		self.dnsbody = dnsbody

	def bytes(self):
		return bytes(self.dnsheader + self.dnsquestion + self.dnsbody)

	def __str__(self):
		"""
		Acts like a variable
		"""
		return str(self.dnsheader + self.dnsquestion + self.dnsbody)

	def parseFlags(self, flags):
		byte = (bytes(flags[:1]), bytes(flags[1:2]))

		# byte[0]
		QR = '1'	# 1 byte
		OPCODE = ''	# 4 bytes
		AA = '1'	# 1 byte
		TC = '0'	# 1 byte
		RD = '0'	# 1 byte

		# byte[1]
		RA = '0'	# 1 byte
		Z = '000'	# 3 bytes
		RCODE = '0000'	# 4 bytes

		for bit in range(1, 5):
			OPCODE += str(ord(byte[0]) & (1 << bit))

		res = int(QR+OPCODE+AA+TC+RD, 2).to_bytes(1, byteorder="big")
		res += int(RA+Z+RCODE, 2).to_bytes(1, byteorder="big")
		return res

	def getquerydomain(self, data):
		state = False
		expectedLength = 0
		domain = ''
		parts = list()
		i = 0
		y = 0

		for byte in data:
			if state:
				if byte != 0:
					domain += chr(byte)
				i += 1

				if i == expectedLength:
					parts.append(domain)
					domain = ''
					state = False
					i = 0
				if byte == 0:
					parts.append(domain)
					break
			else:
				state = True
				expectedLength = byte

			y += 1

		type = data[y:y+2]
		return (parts, type)

	def getreq(self, data):
		domain, type = self.getquerydomain(data)
		qt = ''
		qt = packet[str(int.from_bytes(type, byteorder="big"))].lower()

		zone = self.getzone(domain)
		if zone is None:
			ip = [{
				"value": rdata.to_text(),
				"ttl": 340
				} for rdata in resolver.query('.'.join(domain), qt.upper())]
			return (ip, qt, domain)

		zone = zone[qt.upper()]
		return (zone, qt, domain)

	def getzone(self, domain):
		zone_name = '.'.join(domain)

		try:
			return self.zones[zone_name]
		except:
			return None

	def loadzones(self):
		zonefiles = glob.glob("zones/*.zone")
		jsonzone = dict()

		for zone in zonefiles:
			with open(zone) as zonedata:
				data = json.load(zonedata)
				zonename = data["origin"]
				jsonzone[zonename] = data

		return jsonzone

	def buildquestion(self, domainname, rectype):
		qbytes = b''

		for part in domainname:
			length = len(part)
			qbytes += bytes([length])

			for char in part:
				qbytes += ord(char).to_bytes(1, byteorder="big")

		if rectype == 'a':
			qbytes += (1).to_bytes(2, byteorder="big")

		# 00 01 IN (Internet)
		qbytes += (1).to_bytes(2, byteorder="big")

		return qbytes

	def rectobytes(self, domainname, rectype, recttl, recval):
		rbytes = b'\xc0\x0c'

		if rectype == 'a':
			rbytes = rbytes + bytes([0]) + bytes([1])

		rbytes = rbytes + bytes([0]) + bytes([1])
		rbytes += int(recttl).to_bytes(4, byteorder="big")

		if rectype == 'a':
			rbytes = rbytes + bytes([0]) + bytes([4])

			for part in recval.split('.'):
				rbytes += bytes([int(part)])

		return rbytes
