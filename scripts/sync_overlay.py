#!/usr/bin/env python3
"""
sync_overlay.py
Synchronizes latest rules from origin/master and overlays custom rules:
1. Resets working tree to origin/master.
2. Injects custom Apple Intelligence, OpenAI, and QUIC reject rules into sr_proxy_list.module.
3. Excludes Siri/PCC/iCloud conflicting rules from sr_direct_list.module.
4. Unblocks essential analytics/telemetry/auth services from sr_reject_list.module.
5. Updates factory/ templates and docs/03.shadowsocks_tiny.conf.
6. Re-calculates and updates rule count headers.
"""

import os
import re
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

QUIC_REJECT_RULE = "AND,((PROTOCOL,UDP),(DST-PORT,443)),REJECT-NO-DROP"

PROXY_APPEND_RULES = [
    # OpenAI / ChatGPT
    "DOMAIN,chat.openai.com.cdn.cloudflare.net,PROXY",
    "DOMAIN,openai-api.arkoselabs.com,PROXY",
    "DOMAIN,openaicom-api-bdcpf8c6d2e9atf6.z01.azurefd.net,PROXY",
    "DOMAIN,openaicomproductionae4b.blob.core.windows.net,PROXY",
    "DOMAIN,production-openaicom-storage.azureedge.net,PROXY",
    "DOMAIN,o33249.ingest.sentry.io,PROXY",
    "DOMAIN-KEYWORD,chatgpt,PROXY",
    "DOMAIN-KEYWORD,openaicom-api,PROXY",
    "DOMAIN-SUFFIX,chatgpt.com,PROXY",
    "DOMAIN-SUFFIX,openai.com,PROXY",
    # Apple Intelligence & PCC
    "DOMAIN-SUFFIX,apple-cloudcompute.com,PROXY",
    "DOMAIN-SUFFIX,apple-ai.com,PROXY",
    "DOMAIN,guzzoni.apple.com,PROXY",
    "DOMAIN,api-siri-prod.apple.com,PROXY",
    "DOMAIN-SUFFIX,siri.apple.com,PROXY",
    "DOMAIN-KEYWORD,siri,PROXY",
    "DOMAIN-SUFFIX,smoot.apple.com,PROXY",
    "DOMAIN-SUFFIX,gateway.icloud.com,PROXY",
    "DOMAIN-SUFFIX,apple-relay.apple.com,PROXY",
    "DOMAIN-SUFFIX,apple-relay.cloudflare.com,PROXY",
    "DOMAIN-SUFFIX,apple-relay.fastly-edge.com,PROXY",
    "DOMAIN-SUFFIX,apple-relay.akamaized.net,PROXY",
    "DOMAIN-SUFFIX,apple-relay.mask.apple-dns.net,PROXY",
    "DOMAIN-SUFFIX,mask.icloud.com,PROXY",
    "DOMAIN-SUFFIX,mask-h2.icloud.com,PROXY",
    "DOMAIN-SUFFIX,mask-api.icloud.com,PROXY",
    "DOMAIN-SUFFIX,mask.apple-dns.net,PROXY",
    "DOMAIN-SUFFIX,mask-t.apple-dns.net,PROXY",
    "DOMAIN-SUFFIX,mask-api.fe.apple-dns.net,PROXY",
    "DOMAIN-SUFFIX,cp4.cloudflare.com,PROXY",
    "DOMAIN-SUFFIX,ls.apple.com,PROXY",
    "DOMAIN-SUFFIX,gspe1-ssl.ls.apple.com,PROXY",
    "DOMAIN,guzzoni-apple-com.v.aaplimg.com,PROXY",
    "DOMAIN,swallow-apple-com.v.aaplimg.com,PROXY",
    "DOMAIN,swallow.apple.com,PROXY",
    "DOMAIN,probe.siri.apple.com,PROXY",
    "DOMAIN,seed.siri.apple.com,PROXY",
    "DOMAIN,seed-swallow.siri.apple.com,PROXY",
    "DOMAIN,seed-sequoia.siri.apple.com,PROXY",
    # Additional OpenAI dependencies & telemetry
    "DOMAIN,browser-intake-datadoghq.com,PROXY",
    "DOMAIN,static.cloudflareinsights.com,PROXY",
    "DOMAIN-SUFFIX,ai.com,PROXY",
    "DOMAIN-SUFFIX,algolia.net,PROXY",
    "DOMAIN-SUFFIX,api.statsig.com,PROXY",
    "DOMAIN-SUFFIX,auth0.com,PROXY",
    "DOMAIN-SUFFIX,cdn.cloudflare.net,PROXY",
    "DOMAIN-SUFFIX,challenges.cloudflare.com,PROXY",
    "DOMAIN-SUFFIX,chatgpt.livekit.cloud,PROXY",
    "DOMAIN-SUFFIX,client-api.arkoselabs.com,PROXY",
    "DOMAIN-SUFFIX,events.statsigapi.net,PROXY",
    "DOMAIN-SUFFIX,featuregates.org,PROXY",
    "DOMAIN-SUFFIX,host.livekit.cloud,PROXY",
    "DOMAIN-SUFFIX,identrust.com,PROXY",
    "DOMAIN-SUFFIX,intercom.io,PROXY",
    "DOMAIN-SUFFIX,intercomcdn.com,PROXY",
    "DOMAIN-SUFFIX,launchdarkly.com,PROXY",
    "DOMAIN-SUFFIX,oaistatic.com,PROXY",
    "DOMAIN-SUFFIX,oaiusercontent.com,PROXY",
    "DOMAIN-SUFFIX,observeit.net,PROXY",
    "DOMAIN-SUFFIX,openaiapi-site.azureedge.net,PROXY",
    "DOMAIN-SUFFIX,openaicom.imgix.net,PROXY",
    "DOMAIN-SUFFIX,poe.com,PROXY",
    "DOMAIN-SUFFIX,segment.io,PROXY",
    "DOMAIN-SUFFIX,sentry.io,PROXY",
    "DOMAIN-SUFFIX,stripe.com,PROXY",
    "DOMAIN-SUFFIX,turn.livekit.cloud,PROXY",
    "IP-CIDR,24.199.123.28/32,PROXY,no-resolve",
    "IP-CIDR,45.76.214.191/32,PROXY,no-resolve",
    "IP-CIDR,64.23.132.171/32,PROXY,no-resolve",
    "IP-CIDR,143.198.200.27/32,PROXY,no-resolve",
    "IP-CIDR,159.89.204.203/32,PROXY,no-resolve",
]

DIRECT_EXCLUDE_EXACT = {
    "DOMAIN-SUFFIX,icloud.com,DIRECT",
    "DOMAIN,seed-swallow.siri.apple.com,DIRECT",
    "DOMAIN,seed.siri.apple.com,DIRECT",
    "DOMAIN,guzzoni.apple.com,DIRECT",
    "DOMAIN,guzzoni-apple-com.v.aaplimg.com,DIRECT",
    "DOMAIN,probe.siri.apple.com,DIRECT",
    "DOMAIN,seed-sequoia.siri.apple.com,DIRECT",
    "DOMAIN,guzzoni.smoot.apple.com,DIRECT",
    "DOMAIN,swallow.apple.com,DIRECT",
    "DOMAIN,swallow-apple-com.v.aaplimg.com,DIRECT",
    "DOMAIN,gateway.icloud.com,DIRECT",
    "DOMAIN-SUFFIX,gateway.icloud.com,DIRECT",
    "DOMAIN,mask.icloud.com,DIRECT",
    "DOMAIN-SUFFIX,mask.icloud.com,DIRECT",
    "DOMAIN,mask-h2.icloud.com,DIRECT",
    "DOMAIN-SUFFIX,mask-h2.icloud.com,DIRECT",
    "DOMAIN,mask-api.icloud.com,DIRECT",
    "DOMAIN-SUFFIX,mask-api.icloud.com,DIRECT",
}

REJECT_EXCLUDE_DOMAINS = [
    "featuregates.org",
    "statsigapi.net",
    "statsig.com",
    "statsigcdn.com",
    "datadoghq.com",
    "datadoghq.eu",
    "browser-intake-datadoghq.com",
    "launchdarkly.com",
    "openai.com",
    "chatgpt.com",
    "challenges.cloudflare.com",
    "arkoselabs.com",
    "auth0.com",
    "identrust.com",
    "livekit.cloud",
]


def update_header_count(lines):
    rule_count = 0
    in_rules = False
    desc_idx = -1
    for i, line in enumerate(lines):
        if line.startswith("#!desc="):
            desc_idx = i
        elif line.strip() == "[Rule]":
            in_rules = True
        elif in_rules and line.strip() and not line.startswith("#"):
            rule_count += 1
    if desc_idx != -1:
        lines[desc_idx] = re.sub(r"Rules:\d+", f"Rules:{rule_count}", lines[desc_idx])
    return lines, rule_count


def process_proxy_module(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    header = []
    rules = []
    in_rules = False
    for line in lines:
        stripped = line.strip()
        if stripped == "[Rule]":
            in_rules = True
            header.append(line)
        elif not in_rules:
            header.append(line)
        else:
            if stripped:
                rules.append(stripped)

    existing_set = set(rules)
    new_rules = []
    # Prepend QUIC block
    if QUIC_REJECT_RULE not in existing_set:
        new_rules.append(QUIC_REJECT_RULE)

    # Append custom proxy rules
    for r in PROXY_APPEND_RULES:
        if r not in existing_set and r != QUIC_REJECT_RULE:
            new_rules.append(r)

    # Combine: QUIC rule at top, then existing rules, then append rules
    all_rules = []
    if QUIC_REJECT_RULE not in existing_set:
        all_rules.append(QUIC_REJECT_RULE + "\n")
    for r in rules:
        if r != QUIC_REJECT_RULE:
            all_rules.append(r + "\n")
    for r in PROXY_APPEND_RULES:
        if r not in existing_set and r != QUIC_REJECT_RULE:
            all_rules.append(r + "\n")

    combined = header + all_rules
    combined, count = update_header_count(combined)

    with open(file_path, "w", encoding="utf-8") as f:
        f.writelines(combined)
    print(f"sr_proxy_list.module updated: {count} rules")


def process_direct_module(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    header = []
    rules = []
    in_rules = False
    for line in lines:
        stripped = line.strip()
        if stripped == "[Rule]":
            in_rules = True
            header.append(line)
        elif not in_rules:
            header.append(line)
        else:
            if stripped:
                if stripped in DIRECT_EXCLUDE_EXACT:
                    continue
                rules.append(stripped + "\n")

    combined = header + rules
    combined, count = update_header_count(combined)

    with open(file_path, "w", encoding="utf-8") as f:
        f.writelines(combined)
    print(f"sr_direct_list.module updated: {count} rules")


def process_reject_module(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    header = []
    rules = []
    in_rules = False

    # Regex pattern to match any excluded domain
    exclude_pattern = re.compile(
        r"(?:^|,|\.)(" + "|".join(re.escape(d) for d in REJECT_EXCLUDE_DOMAINS) + r")(?:,|$)",
        re.IGNORECASE,
    )

    removed = 0
    for line in lines:
        stripped = line.strip()
        if stripped == "[Rule]":
            in_rules = True
            header.append(line)
        elif not in_rules:
            header.append(line)
        else:
            if stripped:
                if exclude_pattern.search(stripped):
                    removed += 1
                    continue
                rules.append(stripped + "\n")

    combined = header + rules
    combined, count = update_header_count(combined)

    with open(file_path, "w", encoding="utf-8") as f:
        f.writelines(combined)
    print(f"sr_reject_list.module updated: {count} rules (removed {removed} blocked rules)")


def update_tiny_conf(file_path):
    conf_content = """[General]
# 旁路系统：必须设为 false，确保 iOS 18.2+ 系统级守护进程（Siri、Apple 智能、私有云计算 PCC）走代理
bypass-system = false

# 保留本地网段跳过代理
skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com
tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 255.255.255.255/32, 239.255.255.250/32

# DNS 配置：国内使用系统 DNS，避免因连接外网 DoH 超时导致解析死锁
dns-server = system
fallback-dns-server = system

# IPv6 支持
ipv6 = true
prefer-ipv6 = false

# DNS 回退策略与网络设置
dns-direct-system = false
dns-direct-fallback-proxy = false
icmp-auto-reply = true
always-reject-url-rewrite = false
private-ip-answer = true
udp-policy-not-supported-behaviour = REJECT
use-local-host-item-for-proxy = false

[Rule]
# 1. 阻止 QUIC (HTTP/3 443 UDP)，解决节点关闭/不支持 UDP 导致苹果连接重置断流的问题，强制秒级平滑回退 TCP
AND,((PROTOCOL,UDP),(DST-PORT,443)),REJECT-NO-DROP

# 2. Apple Intelligence & 私有云计算 (PCC) & Siri
DOMAIN-SUFFIX,apple-cloudcompute.com,PROXY
DOMAIN-SUFFIX,apple-ai.com,PROXY
DOMAIN,guzzoni.apple.com,PROXY
DOMAIN,api-siri-prod.apple.com,PROXY
DOMAIN-SUFFIX,siri.apple.com,PROXY
DOMAIN-KEYWORD,siri,PROXY
DOMAIN-SUFFIX,smoot.apple.com,PROXY
DOMAIN-SUFFIX,gateway.icloud.com,PROXY
DOMAIN-SUFFIX,apple-relay.apple.com,PROXY
DOMAIN-SUFFIX,apple-relay.cloudflare.com,PROXY
DOMAIN-SUFFIX,apple-relay.fastly-edge.com,PROXY
DOMAIN-SUFFIX,apple-relay.akamaized.net,PROXY
DOMAIN-SUFFIX,apple-relay.mask.apple-dns.net,PROXY
DOMAIN-SUFFIX,mask.icloud.com,PROXY
DOMAIN-SUFFIX,mask-h2.icloud.com,PROXY
DOMAIN-SUFFIX,mask-api.icloud.com,PROXY
DOMAIN-SUFFIX,mask.apple-dns.net,PROXY
DOMAIN-SUFFIX,mask-t.apple-dns.net,PROXY
DOMAIN-SUFFIX,mask-api.fe.apple-dns.net,PROXY
DOMAIN-SUFFIX,cp4.cloudflare.com,PROXY
DOMAIN-SUFFIX,ls.apple.com,PROXY
DOMAIN-SUFFIX,gspe1-ssl.ls.apple.com,PROXY
DOMAIN,guzzoni-apple-com.v.aaplimg.com,PROXY
DOMAIN,swallow-apple-com.v.aaplimg.com,PROXY
DOMAIN,swallow.apple.com,PROXY
DOMAIN,probe.siri.apple.com,PROXY
DOMAIN,seed.siri.apple.com,PROXY
DOMAIN,seed-swallow.siri.apple.com,PROXY
DOMAIN,seed-sequoia.siri.apple.com,PROXY

# 3. ChatGPT & OpenAI 鉴权服务链与实时通道
DOMAIN,chat.openai.com.cdn.cloudflare.net,PROXY
DOMAIN-KEYWORD,chatgpt,PROXY
DOMAIN-KEYWORD,openai,PROXY
DOMAIN-SUFFIX,chatgpt.com,PROXY
DOMAIN-SUFFIX,openai.com,PROXY
DOMAIN-SUFFIX,oaistatic.com,PROXY
DOMAIN-SUFFIX,oaiusercontent.com,PROXY
DOMAIN,api.statsig.com,PROXY
DOMAIN-SUFFIX,events.statsigapi.net,PROXY
DOMAIN-SUFFIX,featuregates.org,PROXY
DOMAIN,browser-intake-datadoghq.com,PROXY
DOMAIN,o33249.ingest.sentry.io,PROXY
DOMAIN,openai-api.arkoselabs.com,PROXY
DOMAIN-SUFFIX,client-api.arkoselabs.com,PROXY
DOMAIN,openaicom-api-bdcpf8c6d2e9atf6.z01.azurefd.net,PROXY
DOMAIN,openaicomproductionae4b.blob.core.windows.net,PROXY
DOMAIN,production-openaicom-storage.azureedge.net,PROXY
DOMAIN,static.cloudflareinsights.com,PROXY
DOMAIN-KEYWORD,openaicom-api,PROXY
DOMAIN-SUFFIX,algolia.net,PROXY
DOMAIN-SUFFIX,auth0.com,PROXY
DOMAIN-SUFFIX,cdn.cloudflare.net,PROXY
DOMAIN-SUFFIX,challenges.cloudflare.com,PROXY
DOMAIN-SUFFIX,chatgpt.livekit.cloud,PROXY
DOMAIN-SUFFIX,host.livekit.cloud,PROXY
DOMAIN-SUFFIX,turn.livekit.cloud,PROXY
DOMAIN-SUFFIX,identrust.com,PROXY
DOMAIN-SUFFIX,intercom.io,PROXY
DOMAIN-SUFFIX,intercomcdn.com,PROXY
DOMAIN-SUFFIX,launchdarkly.com,PROXY
DOMAIN-SUFFIX,stripe.com,PROXY
IP-CIDR,24.199.123.28/32,PROXY,no-resolve
IP-CIDR,45.76.214.191/32,PROXY,no-resolve
IP-CIDR,64.23.132.171/32,PROXY,no-resolve
IP-CIDR,143.198.200.27/32,PROXY,no-resolve
IP-CIDR,159.89.204.203/32,PROXY,no-resolve

# 4. 基础国别直连与兜底代理
GEOIP,CN,DIRECT
FINAL,PROXY

[MITM]
enable = false
"""
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(conf_content)
    print("docs/03.shadowsocks_tiny.conf updated.")


def main():
    print("=== Shadowrocket Rules Sync & Overlay ===")
    proxy_path = os.path.join(REPO_ROOT, "sr_proxy_list.module")
    direct_path = os.path.join(REPO_ROOT, "sr_direct_list.module")
    reject_path = os.path.join(REPO_ROOT, "sr_reject_list.module")
    conf_path = os.path.join(REPO_ROOT, "docs", "03.shadowsocks_tiny.conf")

    process_proxy_module(proxy_path)
    process_direct_module(direct_path)
    process_reject_module(reject_path)
    update_tiny_conf(conf_path)
    print("=== Overlay complete! ===")


if __name__ == "__main__":
    main()

