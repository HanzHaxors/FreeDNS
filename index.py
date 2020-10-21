import dnslib, glob, json, os
from elevate import elevate

banner = """

  __|               _ \   \ |   __|
  _|  _| -_)   -_)  |  | .  | \__ \\
 _| _| \___| \___| ___/ _|\_| ____/

"""

print(('\r' + banner) if os.getuid() == 0 else "")

def load_zones():
	zonefiles = glob.glob("zones/*.zone")
	jsonzone = dict()

	for zone in zonefiles:
		with open(zone) as zonedata:
			data = json.load(zonedata)
			zonename = data["origin"]
			jsonzone[zonename] = data

	return jsonzone

zone_name = load_zones()

if os.getuid() != 0:
    print("[*] Elevating privileges...")
    elevate(graphical=False) if os.name == "nt" else elevate(show_console=False)
    os.system("cls" if os.name == "nt" else "clear")

resolver = dnslib.DNSResolver()
print("[*] Running DNS on port 53")

try:
	resolver.run()
except KeyboardInterrupt:
	print("\r[i] Closing DNS Gracefully")
except Exception as e:
	print(f"[!] {e}")
