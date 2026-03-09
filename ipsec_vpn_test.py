#!/usr/bin/env python3
"""
IPSec Site-to-Site VPN Automated Test Script
Product: Zyxel USG FLEX 500H / 700H
Tests IKEv2 Policy-Based VPN via Wizard mode

Usage:
    1. Copy config.yaml.example to config.yaml and fill in your credentials/IPs
    2. pip install playwright pyyaml
    3. playwright install chromium
    4. python ipsec_vpn_test.py
"""

import asyncio
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime

import yaml
from playwright.async_api import async_playwright, Page

# ─── Configuration ───────────────────────────────────────────────────────────

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.yaml')

@dataclass
class DUTConfig:
    name: str
    mgmt_ip: str
    wan_ip: str
    lan_subnet: str
    lan_gateway: str

@dataclass
class TestConfig:
    dut_a: DUTConfig
    dut_b: DUTConfig
    pc_b_mgmt: str
    pc_b_lan: str
    pc_c_mgmt: str
    pc_c_lan: str
    dut_user: str
    dut_pass: str
    pc_user: str
    pc_pass: str
    vpn_name: str
    psk: str
    screenshot_dir: str
    headless: bool
    default_lan_cidr: str

def load_config(path: str = CONFIG_FILE) -> TestConfig:
    if not os.path.exists(path):
        print(f'ERROR: Config file not found: {path}')
        print(f'Please copy config.yaml.example to config.yaml and fill in your settings.')
        sys.exit(1)

    with open(path, 'r') as f:
        c = yaml.safe_load(f)

    return TestConfig(
        dut_a=DUTConfig(**c['dut_a']),
        dut_b=DUTConfig(**c['dut_b']),
        pc_b_mgmt=c['pc_b']['mgmt_ip'],
        pc_b_lan=c['pc_b']['lan_ip'],
        pc_c_mgmt=c['pc_c']['mgmt_ip'],
        pc_c_lan=c['pc_c']['lan_ip'],
        dut_user=c['dut_user'],
        dut_pass=c['dut_pass'],
        pc_user=c['pc_user'],
        pc_pass=c['pc_pass'],
        vpn_name=c.get('vpn_name', 'S2S_Test'),
        psk=c.get('psk', 'TestVPN2026psk'),
        screenshot_dir=c.get('screenshot_dir', 'screenshots'),
        headless=c.get('headless', False),
        default_lan_cidr=c.get('default_lan_cidr', '192.168.168.1/24'),
    )

CFG = load_config()

# ─── Test Results ────────────────────────────────────────────────────────────

@dataclass
class TestResult:
    name: str
    passed: bool
    details: str = ''
    output: str = ''  # full raw output from test tool

results: list[TestResult] = []

# ─── SSH Helper ──────────────────────────────────────────────────────────────

def ssh(host: str, cmd: str, timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            ['sshpass', '-p', CFG.pc_pass, 'ssh',
             '-o', 'StrictHostKeyChecking=no',
             f'{CFG.pc_user}@{host}', cmd],
            capture_output=True, text=True, timeout=timeout
        )
        return (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        return 'ERROR: SSH timeout'
    except Exception as e:
        return f'ERROR: {str(e)[:300]}'

# ─── Playwright Helpers ──────────────────────────────────────────────────────

async def login(page: Page, ip: str):
    await page.goto(f'https://{ip}', timeout=30000)
    await page.wait_for_timeout(3000)
    await page.locator('input').first.fill(CFG.dut_user)
    await page.locator('input').nth(1).fill(CFG.dut_pass)
    await page.locator('button:has-text("Login")').click()
    await page.wait_for_timeout(5000)

async def nav_to(page: Page, parent: str, child: str):
    lis = page.locator('li[role="button"]')
    for i in range(await lis.count()):
        t = await lis.nth(i).text_content()
        if re.sub(r'expand_(more|less)', '', t).strip() == parent:
            await lis.nth(i).click()
            await page.wait_for_timeout(1000)
            break
    links = page.locator('a[role="button"]')
    for i in range(await links.count()):
        t = await links.nth(i).text_content()
        if t.strip() == child and await links.nth(i).is_visible():
            await links.nth(i).click()
            await page.wait_for_timeout(3000)
            return

async def click_btn(page: Page, text: str, timeout: int = 5000) -> bool:
    try:
        btn = page.locator(f'button:has-text("{text}")')
        for i in range(await btn.count()):
            if await btn.nth(i).is_visible(timeout=timeout):
                await btn.nth(i).click()
                return True
    except Exception:
        pass
    return False

async def get_form_inputs(page: Page) -> list[dict]:
    return await page.evaluate('''() => {
        const result = [];
        document.querySelectorAll('input').forEach((input, idx) => {
            const rect = input.getBoundingClientRect();
            if (rect.x > 250 && rect.width > 0 && rect.height > 0 &&
                input.offsetParent !== null &&
                !input.readOnly && !input.disabled &&
                input.getAttribute('aria-hidden') !== 'true' &&
                input.tabIndex >= 0 &&
                !input.className.includes('MuiSelect') &&
                !input.className.includes('nativeInput') &&
                (input.type === 'text' || input.type === 'password' || input.type === '')) {
                result.push({ idx, x: Math.round(rect.x), y: Math.round(rect.y),
                              type: input.type, value: input.value });
            }
        });
        return result;
    }''')

def screenshot_path(name: str) -> str:
    return os.path.join(CFG.screenshot_dir, f'{name}.png')

# ─── LAN Subnet Configuration ───────────────────────────────────────────────

async def change_lan(page: Page, dut: DUTConfig, new_cidr: str):
    print(f'  Changing {dut.name} ge3 LAN to {new_cidr}')
    await nav_to(page, 'Network', 'Interface')
    await page.wait_for_timeout(2000)

    ge3_row = page.locator('tr').filter(has_text='ge3').filter(has_text='LAN')
    await ge3_row.locator('input[type="checkbox"]').first.click()
    await page.wait_for_timeout(500)

    edit_btns = page.locator('button').filter(has_text=re.compile(r'^\s*Edit\s*$'))
    count = await edit_btns.count()
    for i in range(count - 1, -1, -1):
        if await edit_btns.nth(i).is_visible():
            await edit_btns.nth(i).click()
            break
    await page.wait_for_timeout(3000)

    all_inputs = page.locator('input[type="text"]')
    for i in range(await all_inputs.count()):
        try:
            val = await all_inputs.nth(i).input_value()
            if val.startswith('192.168.') and '/24' in val:
                await all_inputs.nth(i).click(click_count=3)
                await all_inputs.nth(i).fill(new_cidr)
                print(f'    Changed {val} -> {new_cidr}')
                break
        except Exception:
            pass

    await page.evaluate('window.scrollTo(0, document.body.scrollHeight)')
    await page.wait_for_timeout(1000)
    await page.screenshot(path=screenshot_path(f'{dut.name}-lan-edit'))

    await click_btn(page, 'Apply')
    await page.wait_for_timeout(2000)
    await click_btn(page, 'OK', 5000)
    await page.wait_for_timeout(2000)
    await click_btn(page, 'Apply', 5000)
    await page.wait_for_timeout(5000)
    await click_btn(page, 'OK', 3000)
    await page.wait_for_timeout(3000)

    await page.screenshot(path=screenshot_path(f'{dut.name}-lan-done'))

# ─── VPN Setup via Wizard ────────────────────────────────────────────────────

async def setup_vpn(page: Page, dut: DUTConfig, peer_wan: str,
                    local_subnet: str, remote_subnet: str):
    print(f'\n=== Setting up IPSec VPN on {dut.name} ===')
    await nav_to(page, 'VPN', 'IPSec VPN')
    await page.wait_for_timeout(2000)

    try:
        await page.locator('[role="tab"]').filter(has_text='Site to Site').first.click()
        await page.wait_for_timeout(2000)
    except Exception:
        pass

    # Remove existing
    existing = page.locator('tr').filter(has_text=CFG.vpn_name)
    if await existing.count() > 0:
        print('  Removing existing VPN...')
        await existing.first.locator('input[type="checkbox"]').first.click()
        await page.wait_for_timeout(500)
        await click_btn(page, 'Remove')
        await page.wait_for_timeout(2000)
        await click_btn(page, 'OK', 3000)
        await click_btn(page, 'Apply', 5000)
        await page.wait_for_timeout(3000)

    await click_btn(page, 'Add')
    await page.wait_for_timeout(3000)

    # Step 1: Scenario
    print('  Step 1: Scenario')
    inputs = await get_form_inputs(page)
    if inputs:
        await page.locator('input').nth(inputs[0]['idx']).click()
        await page.locator('input').nth(inputs[0]['idx']).fill(CFG.vpn_name)
        print(f'    Name = {CFG.vpn_name}')
    await page.screenshot(path=screenshot_path(f'{dut.name}-S1'))
    await click_btn(page, 'Next')
    await page.wait_for_timeout(3000)

    # Step 2: Network
    print('  Step 2: Network')
    inputs = await get_form_inputs(page)
    for inp in inputs:
        if inp['value'] == '':
            await page.locator('input').nth(inp['idx']).click()
            await page.locator('input').nth(inp['idx']).fill(peer_wan)
            print(f'    Peer Gateway = {peer_wan}')
            break
    await page.screenshot(path=screenshot_path(f'{dut.name}-S2'))
    await click_btn(page, 'Next')
    await page.wait_for_timeout(3000)

    # Step 3: Authentication
    print('  Step 3: Authentication')
    inputs = await get_form_inputs(page)
    if inputs:
        await page.locator('input').nth(inputs[0]['idx']).click()
        await page.locator('input').nth(inputs[0]['idx']).fill(CFG.psk)
        print(f'    PSK = {CFG.psk}')
    await page.screenshot(path=screenshot_path(f'{dut.name}-S3'))
    await click_btn(page, 'Next')
    await page.wait_for_timeout(3000)

    # Retry PSK if validation failed
    body = await page.text_content('body')
    if 'Pre-Shared Key' in body and 'pre-shared key can be' in body:
        print('    Retrying PSK with alternative input method...')
        all_info = await page.evaluate('''() => {
            const result = [];
            document.querySelectorAll('input').forEach((input, idx) => {
                const rect = input.getBoundingClientRect();
                if (rect.x > 400 && rect.width > 50 && input.offsetParent !== null) {
                    result.push({ idx, type: input.type, value: input.value,
                                  ariaHidden: input.getAttribute('aria-hidden') });
                }
            });
            return result;
        }''')
        for inp in all_info:
            if inp['type'] in ('text', 'password') and inp['value'] == '' and inp['ariaHidden'] != 'true':
                await page.locator('input').nth(inp['idx']).click()
                await page.locator('input').nth(inp['idx']).fill(CFG.psk)
                break
        await page.screenshot(path=screenshot_path(f'{dut.name}-S3b'))
        await click_btn(page, 'Next')
        await page.wait_for_timeout(3000)

    # Step 4: Policy & Routing
    print('  Step 4: Policy & Routing')
    body = await page.text_content('body')
    if 'Policy-Based' in body:
        label = page.locator('label:has-text("Policy-Based")')
        if await label.count() > 0 and await label.first.is_visible():
            await label.first.click()
            await page.wait_for_timeout(1000)

    inputs = await get_form_inputs(page)
    empty = [i for i in inputs if i['value'] == '' or i['value'] == '0.0.0.0']
    if len(empty) >= 2:
        await page.locator('input').nth(empty[0]['idx']).click()
        await page.locator('input').nth(empty[0]['idx']).fill(local_subnet)
        print(f'    Local Subnet = {local_subnet}')
        await page.locator('input').nth(empty[1]['idx']).click()
        await page.locator('input').nth(empty[1]['idx']).fill(remote_subnet)
        print(f'    Remote Subnet = {remote_subnet}')
    elif len(empty) == 1:
        await page.locator('input').nth(empty[0]['idx']).click()
        await page.locator('input').nth(empty[0]['idx']).fill(remote_subnet)
        print(f'    Remote Subnet = {remote_subnet}')

    await page.screenshot(path=screenshot_path(f'{dut.name}-S4'))
    if not await click_btn(page, 'Finish', 3000):
        await click_btn(page, 'Next')
    await page.wait_for_timeout(3000)

    # Step 5: Summary
    print('  Step 5: Summary')
    await page.screenshot(path=screenshot_path(f'{dut.name}-S5'))
    await click_btn(page, 'Close', 5000)
    await page.wait_for_timeout(2000)
    await click_btn(page, 'Apply', 5000)
    await page.wait_for_timeout(5000)
    await click_btn(page, 'OK', 3000)
    await page.wait_for_timeout(2000)

    # Activate
    print('  Activating...')
    await nav_to(page, 'VPN', 'IPSec VPN')
    await page.wait_for_timeout(3000)
    try:
        await page.locator('[role="tab"]').filter(has_text='Site to Site').first.click()
        await page.wait_for_timeout(2000)
    except Exception:
        pass

    vpn_row = page.locator('tr').filter(has_text=CFG.vpn_name)
    if await vpn_row.count() > 0:
        print('  VPN entry found!')
        await vpn_row.first.locator('input[type="checkbox"]').first.click()
        await page.wait_for_timeout(500)
        await click_btn(page, 'Active', 3000)
        await page.wait_for_timeout(2000)
        await click_btn(page, 'Connect', 3000)
        await page.wait_for_timeout(5000)
    else:
        print('  VPN entry not visible in list (may be auto-activated by wizard)')

    await page.screenshot(path=screenshot_path(f'{dut.name}-vpn-status'))

    # Monitor > IPSec
    await nav_to(page, 'Monitor', 'IPSec')
    await page.wait_for_timeout(3000)
    await page.screenshot(path=screenshot_path(f'{dut.name}-monitor-ipsec'))

# ─── Restore DUT Configuration ──────────────────────────────────────────────

async def remove_vpn(page: Page, dut: DUTConfig):
    """Remove the S2S_Test VPN entry from a DUT."""
    print(f'  Removing VPN on {dut.name}...')
    await nav_to(page, 'VPN', 'IPSec VPN')
    await page.wait_for_timeout(3000)

    try:
        await page.locator('[role="tab"]').filter(has_text='Site to Site').first.click()
        await page.wait_for_timeout(2000)
    except Exception:
        pass

    vpn_row = page.locator('tr').filter(has_text=CFG.vpn_name)
    if await vpn_row.count() > 0:
        await vpn_row.first.locator('input[type="checkbox"]').first.click()
        await page.wait_for_timeout(500)
        await click_btn(page, 'Remove')
        await page.wait_for_timeout(2000)
        await click_btn(page, 'OK', 3000)
        await page.wait_for_timeout(2000)
        await click_btn(page, 'Apply', 5000)
        await page.wait_for_timeout(5000)
        await click_btn(page, 'OK', 3000)
        await page.wait_for_timeout(2000)
        print(f'    VPN removed on {dut.name}')
    else:
        print(f'    No VPN entry found on {dut.name}')

async def restore_lan(page: Page, dut: DUTConfig, original_cidr: str):
    """Restore ge3 LAN IP back to original CIDR."""
    print(f'  Restoring {dut.name} ge3 LAN to {original_cidr}')
    await nav_to(page, 'Network', 'Interface')
    await page.wait_for_timeout(2000)

    ge3_row = page.locator('tr').filter(has_text='ge3').filter(has_text='LAN')
    await ge3_row.locator('input[type="checkbox"]').first.click()
    await page.wait_for_timeout(500)

    edit_btns = page.locator('button').filter(has_text=re.compile(r'^\s*Edit\s*$'))
    count = await edit_btns.count()
    for i in range(count - 1, -1, -1):
        if await edit_btns.nth(i).is_visible():
            await edit_btns.nth(i).click()
            break
    await page.wait_for_timeout(3000)

    all_inputs = page.locator('input[type="text"]')
    for i in range(await all_inputs.count()):
        try:
            val = await all_inputs.nth(i).input_value()
            if val.startswith('192.168.') and '/24' in val:
                await all_inputs.nth(i).click(click_count=3)
                await all_inputs.nth(i).fill(original_cidr)
                print(f'    Changed {val} -> {original_cidr}')
                break
        except Exception:
            pass

    await page.evaluate('window.scrollTo(0, document.body.scrollHeight)')
    await page.wait_for_timeout(1000)

    await click_btn(page, 'Apply')
    await page.wait_for_timeout(2000)
    await click_btn(page, 'OK', 5000)
    await page.wait_for_timeout(2000)
    await click_btn(page, 'Apply', 5000)
    await page.wait_for_timeout(5000)
    await click_btn(page, 'OK', 3000)
    await page.wait_for_timeout(3000)
    print(f'    {dut.name} ge3 LAN restored to {original_cidr}')

# ─── Test Functions ──────────────────────────────────────────────────────────

def test_ping(src_mgmt: str, dst_ip: str, test_name: str, count: int = 4) -> TestResult:
    print(f'  {test_name}...')
    output = ssh(src_mgmt, f'ping -c {count} -W 3 {dst_ip} 2>&1')
    print(f'    {output.splitlines()[-1] if output.splitlines() else output}')

    match = re.search(r'(\d+) received', output)
    received = int(match.group(1)) if match else 0
    passed = received > 0

    match_rtt = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', output)
    avg_rtt = match_rtt.group(1) if match_rtt else 'N/A'

    return TestResult(
        name=test_name, passed=passed,
        details=f'{received}/{count} packets, avg RTT={avg_rtt}ms',
        output=output
    )

def test_iperf3(src_mgmt: str, dst_ip: str, server_mgmt: str,
                test_name: str, duration: int = 10) -> TestResult:
    print(f'  {test_name}...')
    ssh(server_mgmt, 'pkill iperf3 2>/dev/null; iperf3 -s -D --one-off 2>&1')
    time.sleep(2)

    output = ssh(src_mgmt, f'iperf3 -c {dst_ip} -t {duration} 2>&1', timeout=duration + 15)
    ssh(server_mgmt, 'pkill iperf3 2>/dev/null')

    bitrate = 'N/A'
    sender_lines = [l for l in output.splitlines() if 'sender' in l]
    if sender_lines:
        parts = sender_lines[0].split()
        for i, p in enumerate(parts):
            if 'bits/sec' in p:
                bitrate = parts[i-1] + ' ' + p
                break

    passed = 'iperf Done' in output or 'sender' in output
    print(f'    Bitrate: {bitrate}')

    return TestResult(name=test_name, passed=passed,
                      details=f'Bitrate: {bitrate}', output=output)

def test_traceroute(src_mgmt: str, dst_ip: str, test_name: str) -> TestResult:
    print(f'  {test_name}...')
    output = ssh(src_mgmt, f'traceroute -n -w 3 -m 5 {dst_ip} 2>&1')
    print(f'    {output}')

    hop_lines = [l for l in output.splitlines() if re.match(r'\s*\d+\s', l)]
    passed = len(hop_lines) >= 2 and dst_ip in output

    return TestResult(name=test_name, passed=passed,
                      details=f'{len(hop_lines)} hops', output=output)

def test_mtu(src_mgmt: str, dst_ip: str, test_name: str, size: int = 1400) -> TestResult:
    print(f'  {test_name}...')
    output = ssh(src_mgmt, f'ping -c 4 -W 3 -s {size} -M do {dst_ip} 2>&1')
    print(f'    {output.splitlines()[-1] if output.splitlines() else output}')

    match = re.search(r'(\d+) received', output)
    received = int(match.group(1)) if match else 0
    passed = received > 0

    return TestResult(name=test_name, passed=passed,
                      details=f'{received}/4 packets with {size}B payload',
                      output=output)

def test_tcp(src_mgmt: str, dst_ip: str, server_mgmt: str, test_name: str) -> TestResult:
    print(f'  {test_name}...')
    ssh(server_mgmt, 'echo "VPN_TUNNEL_OK" | nc -l -p 9999 -w 5 &')
    time.sleep(1)
    output = ssh(src_mgmt, f'echo "HELLO" | nc -w 3 {dst_ip} 9999 2>&1')
    print(f'    Response: {output}')

    passed = 'VPN_TUNNEL_OK' in output
    return TestResult(name=test_name, passed=passed,
                      details=f'Response: {output}', output=output)

# ─── Report Generation ──────────────────────────────────────────────────────

def generate_report(test_results: list[TestResult]) -> str:
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    total = len(test_results)
    passed = sum(1 for r in test_results if r.passed)
    failed = total - passed
    sd = CFG.screenshot_dir

    lines = []
    lines.append('# IPSec Site-to-Site VPN Automated Test Report')
    lines.append('')
    lines.append(f'**Product**: Zyxel USG FLEX 500H / 700H')
    lines.append(f'**Test Date**: {now}')
    lines.append(f'**VPN Type**: IKEv2 Site-to-Site, Policy-Based, Wizard Mode')
    lines.append(f'**Overall Result**: {"PASS" if failed == 0 else "FAIL"} ({passed}/{total} tests passed)')
    lines.append('')
    lines.append('---')
    lines.append('')

    # ── Topology ──
    lines.append('## 1. Test Environment')
    lines.append('')
    lines.append('```')
    lines.append('PC-B (192.168.1.34/24)          PC-C (192.168.2.34/24)')
    lines.append('        |                               |')
    lines.append('    [ge3 LAN]                       [ge3 LAN]')
    lines.append('   DUT-A (USG FLEX)              DUT-B (USG FLEX)')
    lines.append('    [ge1 WAN]                       [ge1 WAN]')
    lines.append('  192.168.111.37  ──── WAN ────  192.168.111.36')
    lines.append('                  IPSec Tunnel')
    lines.append('```')
    lines.append('')
    lines.append('| Device | Management IP | WAN IP | LAN Subnet |')
    lines.append('|--------|---------------|--------|------------|')
    lines.append(f'| DUT-A | {CFG.dut_a.mgmt_ip} | {CFG.dut_a.wan_ip} | {CFG.dut_a.lan_subnet} |')
    lines.append(f'| DUT-B | {CFG.dut_b.mgmt_ip} | {CFG.dut_b.wan_ip} | {CFG.dut_b.lan_subnet} |')
    lines.append(f'| PC-B | {CFG.pc_b_mgmt} | - | {CFG.pc_b_lan}/24 |')
    lines.append(f'| PC-C | {CFG.pc_c_mgmt} | - | {CFG.pc_c_lan}/24 |')
    lines.append('')
    lines.append('| VPN Parameter | Value |')
    lines.append('|---------------|-------|')
    lines.append(f'| VPN Name | {CFG.vpn_name} |')
    lines.append('| IKE Version | IKEv2 |')
    lines.append('| Authentication | Pre-Shared Key |')
    lines.append('| Mode | Policy-Based |')
    lines.append(f'| DUT-A Local/Remote | {CFG.dut_a.lan_subnet} / {CFG.dut_b.lan_subnet} |')
    lines.append(f'| DUT-B Local/Remote | {CFG.dut_b.lan_subnet} / {CFG.dut_a.lan_subnet} |')
    lines.append('')
    lines.append('---')
    lines.append('')

    # ── LAN Configuration Screenshots ──
    lines.append('## 2. LAN Subnet Configuration')
    lines.append('')
    lines.append('### DUT-A: ge3 LAN -> 192.168.1.1/24')
    lines.append('')
    lines.append(f'![DUT-A LAN Edit]({sd}/DUT-A-lan-edit.png)')
    lines.append('')
    lines.append(f'![DUT-A LAN Done]({sd}/DUT-A-lan-done.png)')
    lines.append('')
    lines.append('### DUT-B: ge3 LAN -> 192.168.2.1/24')
    lines.append('')
    lines.append(f'![DUT-B LAN Edit]({sd}/DUT-B-lan-edit.png)')
    lines.append('')
    lines.append(f'![DUT-B LAN Done]({sd}/DUT-B-lan-done.png)')
    lines.append('')
    lines.append('---')
    lines.append('')

    # ── VPN Wizard Screenshots ──
    lines.append('## 3. VPN Configuration (Wizard)')
    lines.append('')

    for dut_name, peer in [('DUT-A', CFG.dut_b.wan_ip), ('DUT-B', CFG.dut_a.wan_ip)]:
        lines.append(f'### {dut_name}')
        lines.append('')
        lines.append(f'**Step 1: Scenario** (Name: {CFG.vpn_name}, IKEv2)')
        lines.append('')
        lines.append(f'![{dut_name} Step 1]({sd}/{dut_name}-S1.png)')
        lines.append('')
        lines.append(f'**Step 2: Network** (Peer Gateway: {peer})')
        lines.append('')
        lines.append(f'![{dut_name} Step 2]({sd}/{dut_name}-S2.png)')
        lines.append('')
        lines.append(f'**Step 3: Authentication** (Pre-Shared Key)')
        lines.append('')
        lines.append(f'![{dut_name} Step 3]({sd}/{dut_name}-S3.png)')
        lines.append('')
        lines.append(f'**Step 4: Policy & Routing** (Policy-Based)')
        lines.append('')
        lines.append(f'![{dut_name} Step 4]({sd}/{dut_name}-S4.png)')
        lines.append('')
        lines.append(f'**Step 5: Summary**')
        lines.append('')
        lines.append(f'![{dut_name} Step 5]({sd}/{dut_name}-S5.png)')
        lines.append('')

    lines.append('### VPN Status')
    lines.append('')
    lines.append(f'![DUT-A VPN Status]({sd}/DUT-A-vpn-status.png)')
    lines.append('')
    lines.append(f'![DUT-B VPN Status]({sd}/DUT-B-vpn-status.png)')
    lines.append('')
    lines.append('### IPSec Monitor')
    lines.append('')
    lines.append(f'![DUT-A IPSec Monitor]({sd}/DUT-A-monitor-ipsec.png)')
    lines.append('')
    lines.append(f'![DUT-B IPSec Monitor]({sd}/DUT-B-monitor-ipsec.png)')
    lines.append('')
    lines.append('---')
    lines.append('')

    # ── Test Results with full output ──
    lines.append('## 4. Test Results')
    lines.append('')
    lines.append('### Summary Table')
    lines.append('')
    lines.append('| # | Test | Result | Details |')
    lines.append('|---|------|:------:|---------|')
    for i, r in enumerate(test_results, 1):
        status = 'PASS' if r.passed else 'FAIL'
        lines.append(f'| {i} | {r.name} | {status} | {r.details} |')
    lines.append('')

    # Full output for each test
    lines.append('### Detailed Test Output')
    lines.append('')
    for i, r in enumerate(test_results, 1):
        status = 'PASS' if r.passed else 'FAIL'
        lines.append(f'#### TC-{i:02d}: {r.name} [{status}]')
        lines.append('')
        lines.append('```')
        lines.append(r.output)
        lines.append('```')
        lines.append('')

    lines.append('---')
    lines.append('')

    # ── Overall Summary ──
    lines.append('## 5. Overall Summary')
    lines.append('')
    lines.append('| Category | Tests | Passed | Failed |')
    lines.append('|----------|:-----:|:------:|:------:|')

    categories = {
        'ICMP Ping': [r for r in test_results if 'ping' in r.name.lower() or 'cross-tunnel' in r.name.lower() or 'LAN gateway' in r.name],
        'Throughput (iperf3)': [r for r in test_results if 'iperf' in r.name.lower()],
        'Routing (traceroute)': [r for r in test_results if 'traceroute' in r.name.lower() or 'Traceroute' in r.name],
        'MTU': [r for r in test_results if 'mtu' in r.name.lower() or 'MTU' in r.name],
        'TCP': [r for r in test_results if 'tcp' in r.name.lower() or 'TCP' in r.name or 'netcat' in r.name.lower()],
    }

    for cat, cat_results in categories.items():
        if cat_results:
            cp = sum(1 for r in cat_results if r.passed)
            cf = len(cat_results) - cp
            lines.append(f'| {cat} | {len(cat_results)} | {cp} | {cf} |')

    lines.append(f'| **Total** | **{total}** | **{passed}** | **{failed}** |')
    lines.append('')
    lines.append(f'### Overall Result: {"PASS" if failed == 0 else "FAIL"}')
    lines.append('')

    return '\n'.join(lines)

# ─── Main ────────────────────────────────────────────────────────────────────

async def main():
    os.makedirs(CFG.screenshot_dir, exist_ok=True)
    results.clear()

    print('=' * 60)
    print('IPSec Site-to-Site VPN Automated Test')
    print('=' * 60)

    async with async_playwright() as p:
        # ── Phase 1: Configure LAN subnets ──
        print('\n--- Phase 1: LAN Subnet Configuration ---')
        for dut, cidr in [(CFG.dut_a, '192.168.1.1/24'), (CFG.dut_b, '192.168.2.1/24')]:
            browser = await p.chromium.launch(headless=CFG.headless)
            page = await browser.new_page(ignore_https_errors=True)
            page.set_default_timeout(20000)
            await login(page, dut.mgmt_ip)
            await change_lan(page, dut, cidr)
            await browser.close()

        print('\n  Waiting 10s for LAN changes to take effect...')
        await asyncio.sleep(10)

        # DHCP renew on PCs
        print('  Renewing DHCP on PCs...')
        ssh(CFG.pc_b_mgmt, f'echo {CFG.pc_pass} | sudo -S networkctl reconfigure enp2s0 2>/dev/null')
        ssh(CFG.pc_c_mgmt, f'echo {CFG.pc_pass} | sudo -S networkctl reconfigure enp2s0 2>/dev/null')
        await asyncio.sleep(5)

        pc_b_ip = ssh(CFG.pc_b_mgmt, "ip -4 addr show enp2s0 | grep 'inet ' | awk '{print $2}'")
        pc_c_ip = ssh(CFG.pc_c_mgmt, "ip -4 addr show enp2s0 | grep 'inet ' | awk '{print $2}'")
        print(f'  PC-B: {pc_b_ip}, PC-C: {pc_c_ip}')

        # Update actual LAN IPs (DHCP may assign different IPs than config)
        if pc_b_ip and '/' in pc_b_ip:
            CFG.pc_b_lan = pc_b_ip.split('/')[0]
        if pc_c_ip and '/' in pc_c_ip:
            CFG.pc_c_lan = pc_c_ip.split('/')[0]
        print(f'  Using PC-B LAN: {CFG.pc_b_lan}, PC-C LAN: {CFG.pc_c_lan}')

        # ── Phase 2: Configure VPN ──
        print('\n--- Phase 2: VPN Configuration ---')
        for dut, peer_wan, local_sub, remote_sub in [
            (CFG.dut_a, CFG.dut_b.wan_ip, CFG.dut_a.lan_subnet, CFG.dut_b.lan_subnet),
            (CFG.dut_b, CFG.dut_a.wan_ip, CFG.dut_b.lan_subnet, CFG.dut_a.lan_subnet),
        ]:
            browser = await p.chromium.launch(headless=CFG.headless)
            page = await browser.new_page(ignore_https_errors=True)
            page.set_default_timeout(20000)
            await login(page, dut.mgmt_ip)
            await setup_vpn(page, dut, peer_wan, local_sub, remote_sub)
            await browser.close()

        print('\n  Waiting 15s for VPN tunnel to establish...')
        await asyncio.sleep(15)

    # ── Phase 3: Run Tests ──
    print('\n--- Phase 3: Connectivity Tests ---')

    results.append(test_ping(CFG.pc_b_mgmt, CFG.dut_b.lan_gateway,
                             f'PC-B -> DUT-B LAN gateway ({CFG.dut_b.lan_gateway})'))
    results.append(test_ping(CFG.pc_c_mgmt, CFG.dut_a.lan_gateway,
                             f'PC-C -> DUT-A LAN gateway ({CFG.dut_a.lan_gateway})'))
    results.append(test_ping(CFG.pc_b_mgmt, CFG.pc_c_lan,
                             f'PC-B -> PC-C cross-tunnel ({CFG.pc_c_lan})'))
    results.append(test_ping(CFG.pc_c_mgmt, CFG.pc_b_lan,
                             f'PC-C -> PC-B cross-tunnel ({CFG.pc_b_lan})'))
    results.append(test_iperf3(CFG.pc_b_mgmt, CFG.pc_c_lan, CFG.pc_c_mgmt,
                               f'iperf3 PC-B -> PC-C throughput'))
    results.append(test_iperf3(CFG.pc_c_mgmt, CFG.pc_b_lan, CFG.pc_b_mgmt,
                               f'iperf3 PC-C -> PC-B throughput'))
    results.append(test_traceroute(CFG.pc_b_mgmt, CFG.pc_c_lan,
                                   f'Traceroute PC-B -> PC-C'))
    results.append(test_traceroute(CFG.pc_c_mgmt, CFG.pc_b_lan,
                                   f'Traceroute PC-C -> PC-B'))
    results.append(test_mtu(CFG.pc_b_mgmt, CFG.pc_c_lan,
                            f'MTU 1400B DF-bit ping'))
    results.append(test_tcp(CFG.pc_b_mgmt, CFG.pc_c_lan, CFG.pc_c_mgmt,
                            f'TCP connectivity via netcat'))

    # ── Phase 4: Report ──
    print('\n--- Phase 4: Generating Report ---')
    report = generate_report(results)
    report_path = 'IPSec_VPN_Test_Report.md'
    with open(report_path, 'w') as f:
        f.write(report)
    print(f'Report saved to {report_path}')

    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed
    print(f'\nTotal: {len(results)} tests, {passed} passed, {failed} failed')
    print(f'Overall: {"PASS" if failed == 0 else "FAIL"}')

    # ── Phase 5: Restore DUT Configuration ──
    print('\n--- Phase 5: Restoring DUT Configuration ---')
    async with async_playwright() as p:
        for dut in [CFG.dut_a, CFG.dut_b]:
            browser = await p.chromium.launch(headless=CFG.headless)
            page = await browser.new_page(ignore_https_errors=True)
            page.set_default_timeout(20000)
            await login(page, dut.mgmt_ip)
            await remove_vpn(page, dut)
            await restore_lan(page, dut, CFG.default_lan_cidr)
            await browser.close()

        print('\n  Waiting 10s for changes to take effect...')
        await asyncio.sleep(10)

        # Renew DHCP on PCs
        print('  Renewing DHCP on PCs...')
        ssh(CFG.pc_b_mgmt, f'echo {CFG.pc_pass} | sudo -S networkctl reconfigure enp2s0 2>/dev/null')
        ssh(CFG.pc_c_mgmt, f'echo {CFG.pc_pass} | sudo -S networkctl reconfigure enp2s0 2>/dev/null')
        await asyncio.sleep(5)

        pc_b_ip = ssh(CFG.pc_b_mgmt, "ip -4 addr show enp2s0 | grep 'inet ' | awk '{print $2}'")
        pc_c_ip = ssh(CFG.pc_c_mgmt, "ip -4 addr show enp2s0 | grep 'inet ' | awk '{print $2}'")
        print(f'  PC-B: {pc_b_ip}, PC-C: {pc_c_ip}')
        print('  DUT configuration restored.')

    return 0 if failed == 0 else 1

if __name__ == '__main__':
    sys.exit(asyncio.run(main()))
