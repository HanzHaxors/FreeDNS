import json

hasil = ""
hasil_json = dict()

packet = dict()
packet["A"] = 1
packet["AAAA"] = 28
packet["AFSDB"] = 18
packet["APL"] = 42
packet["CAA"] = 257
packet["CDNSKEY"] = 60
packet["XDS"] = 59
packet["CERT"] = 37
packet["CNAME"] = 5
packet["CSYNC"] = 62
packet["DHCID"] = 49
packet["DLV"] = 32769
packet["DNAME"] = 39
packet["DNSKEY"] = 48
packet["DS"] = 43
packet["EUI48"] = 108
packet["HINFO"] = 13
packet["HIP"] = 55
packet["IPSECKEY"] = 45
packet["KEY"] = 25
packet["KX"] = 36
packet["LOC"] = 29
packet["MX"] = 15
packet["NAPTR"] = 35
packet["NS"] = 2
packet["NSEC"] = 47
packet["NSEC3"] = 50
packet["NSEC3PARAM"] = 51
packet["OPENPGPKEY"] = 61
packet["PTR"] = 12
packet["RRSIG"] = 46
packet["RP"] = 17
packet["SIG"] = 24
packet["SMIMEA"] = 53
packet["SOA"] = 6
packet["SRV"] = 33
packet["SSHFP"] = 44
packet["TA"] = 32768
packet["TKEY"] = 249
packet["TLSA"] = 52
packet["TSIG"] = 250
packet["TXT"] = 16
packet["URI"] = 256
packet["ZONEMD"] = 63
packet["SVCB"] = 64
packet["HTTPS"] = 65

print("[i] Records are divided by '|' symbol")
print("[i] ex. A|AAAA|SVCB")
selected_record = input("[#] Records: ").split('|')
hasil_json["origin"] = input("[#] Domain: ")
if hasil_json["origin"][len(hasil_json["origin"]) - 1] != '.':
    hasil_json["origin"] += '.'
hasil_json["ttl"] = int(input("[#] Time-To-Live: "))

for record in selected_record:
    tmp = list()
    while True:
        _tmp = dict()
        _tmp["name"] = input(f"[#] Input {record} name: ")
        _tmp["value"] = input(f"[#] Input {record} value: ")
        _tmp["ttl"] = int(input(f"[#] Input {record} time-to-live: ") or 0)

        if not _tmp["name"] or not _tmp["value"] or _tmp["ttl"] == 0:
            break
        tmp.append(_tmp)
    hasil_json[record] = tmp

hasil = json.dumps(hasil_json, indent="\t")
print(hasil)
with open(f"./zones/{hasil_json['origin']}zone", "w") as f:
    # ./zones/hanz.dalc.zone
    f.write(hasil)
