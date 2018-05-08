from time import strptime, time
import subprocess
import dateutil.parser as dp
import re
from ua_parser import user_agent_parser
import redis

r = redis.StrictRedis(host="localhost", port=6379)


def get_block_ips():
    ips = {}
    with open("/var/log/nginx/access.log") as f:
        for line in f:
            lineformat = re.compile(
                r"""(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<dateandtime>\d{2}\/[a-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] ((\"(GET|POST) )(?P<url>.+)(http\/1\.1")) (?P<statuscode>\d{3}) (?P<bytessent>\d+) (["](?P<refferer>(\-)|(.+))["]) (["](?P<useragent>.+)["])""",
                re.IGNORECASE)
            data = re.search(lineformat, line)
            if data:
                datadict = data.groupdict()
                ip = datadict["ipaddress"]
                datetimestring = datadict["dateandtime"]
                user_agent = datadict["useragent"]
                parsed_string = user_agent_parser.ParseUserAgent(user_agent)
                browser = parsed_string["family"]
                refferer = datadict["refferer"]
                method = data.group(6)
                t = datetimestring.split()
                struct_time = strptime(t[0], "%d/%b/%Y:%H:%M:%S")
                iso_8601_time = "{}-{}-{}T{}:{}:{}+{}:{}".format(struct_time.tm_year,
                                                                 struct_time.tm_mon,
                                                                 struct_time.tm_mday,
                                                                 struct_time.tm_hour,
                                                                 struct_time.tm_min,
                                                                 struct_time.tm_sec,
                                                                 t[1][1:3],
                                                                 t[1][-2:]
                                                                 )
                parsed_time = dp.parse(iso_8601_time)
                t_in_seconds = float(parsed_time.strftime("%s"))

                if method == "GET":
                    if ip not in ips:
                        ips[ip] = {"begin_time": t_in_seconds,
                                   "request_time": 0.0,
                                   "status": True,
                                   "hits": 1,
                                   "time_blocked": "",
                                   "is_bot": False,
                                   "from_facebook": False
                                   }
                    else:
                        if ips[ip]["status"] is False or ips[ip]["is_bot"] is True or ips[ip]["from_facebook"] is True:
                            continue

                        if browser == "Googlebot" or browser == "bingbot":
                            command = subprocess.Popen(['host', ip], stdout=subprocess.PIPE)
                            text = command.stdout.read().decode('utf-8')
                            if "domain name pointer" in text:
                                ips[ip]["is_bot"] = True
                                continue

                        if browser == "Facebook" and "facebook.com" not in refferer:
                            ips[ip]["from_facebook"] = True
                            continue

                        ips[ip]["request_time"] = t_in_seconds - ips[ip]["begin_time"]
                        ips[ip]["hits"] += 1

                        if ips[ip]["request_time"] < 60.0 and ips[ip]["hits"] > 120:
                            ips[ip]["status"] = False
                            ips[ip]["time_blocked"] = datetimestring
                            r.set(ip, ip, 7 * 86400)
                            subprocess.Popen(['host', ip], stdout=subprocess.PIPE)
                            continue
                        elif ips[ip]["request_time"] > 60.0:
                            ips[ip]["begin_time"] = t_in_seconds
                            ips[ip]["request_time"] = 0.0
                            ips[ip]["hits"] = 1
    del ips


def block_ip():
    try:
        subprocess.check_call("ipset create Blacklist hash:ip".split(" "))
        subprocess.check_call("iptables -I INPUT -m set --match-set Blacklist src -j DROP".split(" "))
    except subprocess.CalledProcessError:
        pass
    if len(r.keys()) != 0:
        subprocess.check_call("iptables -D INPUT -m set --match-set Blacklist src -j DROP".split(" "))
        subprocess.check_call("ipset destroy Blacklist".split(" "))
        subprocess.check_call("ipset create Blacklist hash:ip".split(" "))
        for ip in r.keys():
            ip = ip.decode("utf-8")
            subprocess.check_call(["ipset", "add", "Blacklist", ip])
        subprocess.check_call("iptables -I INPUT -m set --match-set Blacklist src -j DROP".split(" "))
    else:
        subprocess.check_call("ipset flush Blacklist".split(" "))


def main():
    get_block_ips()
    block_ip()


if __name__ == '__main__':
    main()
