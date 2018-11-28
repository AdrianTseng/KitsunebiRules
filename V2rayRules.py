#!/usr/bin/env python3

from subprocess import call
from os.path import isdir, split, realpath, join
from sys import stderr
from base64 import b64decode
from re import compile, search


DIR = split(realpath(__file__))[0]
GFW_LIST_DIR = join(DIR, "gfw_list")
AD_BLOCK_DIR = join(DIR, "ad_block_list")

initialization_required = True

if isdir(GFW_LIST_DIR):
    if isdir(join(GFW_LIST_DIR, ".git")):
        return_code = call(["cd", GFW_LIST_DIR, "&&", "git", "pull", "&&", "cd", "DIR"])
        initialization_required = False if return_code == 0 else True
    else:
        return_code = call(["rm", "-rf", GFW_LIST_DIR])
        if return_code == 0:
            initialization_required = True
        else:
            stderr.write("发现损坏的 GFW List 目录，请手动删除 '%s' 目录后再次运行程序\n", GFW_LIST_DIR)
            exit(-1)

if initialization_required:
    return_code = call(["git", "clone", "https://github.com/gfwlist/gfwlist.git", GFW_LIST_DIR])
    if return_code != 0:
        stderr.write("无法克隆 GFW List 至 '%s' 目录，请检查！\n", GFW_LIST_DIR)
        exit(-1)

initialization_required = True

if isdir(AD_BLOCK_DIR):
    if isdir(join(AD_BLOCK_DIR, ".git")):
        return_code = call(["cd", AD_BLOCK_DIR, "&&", "git", "pull", "&&", "cd", "DIR"])
        initialization_required = False if return_code == 0 else True
    else:
        return_code = call(["rm", "-rf", AD_BLOCK_DIR])
        if return_code == 0:
            initialization_required = True
        else:
            stderr.write("发现损坏的 AD block 目录，请手动删除 '%s' 目录后再次运行程序\n", AD_BLOCK_DIR)
            exit(-1)

if initialization_required:
    return_code = call(["git", "clone", "https://github.com/felix-fly/v2ray-adlist.git", AD_BLOCK_DIR])
    if return_code != 0:
        stderr.write("无法克隆 AD Block 至 '%s' 目录，请检查！\n", AD_BLOCK_DIR)
        exit(-1)

gfw_list_file = join(GFW_LIST_DIR, "gfwlist.txt")
file = open(gfw_list_file, mode="r")
gfw_list_content = file.read()
file.close()
gfw_list = b64decode(gfw_list_content).decode("utf-8")
gfw_list_rows = gfw_list.split("\n")

pattern_domain = compile(r'^(?=^.{3,255}$)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$')
pattern_vast_domain = compile(
    r'^(?=^.{3,255}$)[a-zA-Z0-9,\*][-a-zA-Z0-9,\*]{0,62}(\.[a-zA-Z0-9,\*][-a-zA-Z0-9,\*]{0,62})+$')


def strip_vast_domain(origin_url):
    urls = origin_url.split(".")
    index = 0
    for each in urls:
        index += 1
        if "*" in each:
            break
    res = ".".join(urls[index:])
    return res


def strict_format(address_type, address, proxy_type):
    if "*" in address:
        domain = search(r"(?<=//).*?(?=/)", address) or search(r"(?<=//).*?(?=$)", address)
        if domain is not None:
            matched = address[domain.start():domain.end()].replace("/", "")
            d_str = pattern_domain.search(matched)
            if d_str is None:
                return "DOMAIN-SUFFIX,%s,%s" % (strip_vast_domain(matched), proxy_type)
            else:
                return "DOMAIN-SUFFIX,%s,%s" % (matched, proxy_type)

        domain = pattern_vast_domain.search(address)
        if domain is not None:
            return "DOMAIN-SUFFIX,%s,%s" % (strip_vast_domain(address), proxy_type)

    return "%s,%s,%s" % (address_type, address, proxy_type)


rules = []
pattern_suffix = compile(r'(?<=^\|\|).*?(?=$)')
pattern_user_agent = compile(r'(?<=^\|).*?(?=$)')
pattern_ip = compile(r'((?:(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d))\.){3}(?:25[0-5]|2[0-4]\d|(?:1\d{2}|[1-9]?\d)))')
for each in gfw_list_rows:
    row = pattern_suffix.search(each)
    if row is not None:
        ip = pattern_ip.search(row.string)
        if ip is not None:
            rules.append("IP-CIDR,%s,PROXY" % each[ip.start(): ip.end()])
        else:
            rules.append(strict_format("DOMAIN-SUFFIX", each[row.start(): row.end()], "PROXY"))
    else:
        row = pattern_user_agent.search(each)
        if row is not None:
            ip = pattern_ip.search(row.string)
            if ip is not None:
                rules.append("IP-CIDR,%s,PROXY" % each[ip.start(): ip.end()])
            else:
                rules.append(strict_format("USER-AGENT", each[row.start(): row.end()], "PROXY"))

wrong_rules = [each for each in rules if "*" in each]

ad_block_file = join(AD_BLOCK_DIR, "site", "ad")
ad_file = open(ad_block_file, 'r')
ad_content = ad_file.read().split("\n")
ad_file.close()
for each in ad_content:
    try:
        rules.append("DOMAIN-SUFFIX,%s,BLOCK" % each if each[0] != "." else each[1:])
    except IndexError:
        print(each)

rules = list(set(rules))
res_file = open(join(DIR, "personal.conf"), 'w')
res_file.write("// Personal Kitsunebi Configures\n\n")
res_file.write("[Rule]\n\n")
[res_file.write("%s\n" % each) for each in rules]
res_file.write("\nFINAL,DIRECT")
res_file.close()

