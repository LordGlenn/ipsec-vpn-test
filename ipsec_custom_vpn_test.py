#!/usr/bin/env python3
"""
IPSec Site-to-Site VPN Custom Configuration Automated Test Script
Product: Zyxel USG FLEX 500H / 700H
Tests 5 Custom VPN configurations with different IKEv1/IKEv2 + encryption/auth combinations

Usage:
    1. Copy config.yaml.example to config.yaml and fill in your credentials/IPs
    2. pip install playwright pyyaml
    3. playwright install chromium
    4. python ipsec_custom_vpn_test.py
"""

import asyncio
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Tuple

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

# ─── Custom VPN Test Cases ──────────────────────────────────────────────────

@dataclass
class CustomVPNCase:
    name: str
    ike_version: str       # "1" or "2"
    vpn_type: str          # "Policy-based" or "Route-based"
    p1_enc: str
    p1_auth: str
    p1_dh: str             # DH group for IKEv1 (single-select); None for IKEv2 defaults
    p2_enc: str
    p2_auth: str
    description: str = ''

CUSTOM_CASES = [
    CustomVPNCase(
        name='Custom_IKEv2_AES256_SHA256',
        ike_version='2', vpn_type='Policy-based',
        p1_enc='aes256-cbc', p1_auth='hmac-sha256', p1_dh=None,
        p2_enc='aes256-cbc', p2_auth='hmac-sha256',
        description='IKEv2 + AES256-CBC + SHA256 + DH defaults',
    ),
    CustomVPNCase(
        name='Custom_IKEv2_AES128GCM_SHA512',
        ike_version='2', vpn_type='Policy-based',
        p1_enc='aes128-gcm-128', p1_auth='hmac-sha512', p1_dh=None,
        p2_enc='aes128-gcm-128', p2_auth='',
        description='IKEv2 + AES128-GCM + SHA512 + DH defaults',
    ),
    CustomVPNCase(
        name='Custom_IKEv1_AES256_SHA256',
        ike_version='1', vpn_type='Policy-based',
        p1_enc='aes256-cbc', p1_auth='hmac-sha256', p1_dh=None,
        p2_enc='aes256-cbc', p2_auth='hmac-sha256',
        description='IKEv1 + AES256-CBC + SHA256 + DH defaults',
    ),
    CustomVPNCase(
        name='Custom_IKEv1_3DES_SHA1',
        ike_version='1', vpn_type='Policy-based',
        p1_enc='3des-cbc', p1_auth='hmac-sha1', p1_dh=None,
        p2_enc='3des-cbc', p2_auth='hmac-sha1',
        description='IKEv1 + 3DES + SHA1 + DH defaults (legacy)',
    ),
    CustomVPNCase(
        name='Custom_IKEv2_AES256GCM_SHA384',
        ike_version='2', vpn_type='Policy-based',
        p1_enc='aes256-gcm-128', p1_auth='hmac-sha384', p1_dh=None,
        p2_enc='aes256-gcm-128', p2_auth='',
        description='IKEv2 + AES256-GCM + SHA384 + DH defaults',
    ),
]

# ─── Test Results ────────────────────────────────────────────────────────────

@dataclass
class TestResult:
    name: str
    passed: bool
    details: str = ''
    output: str = ''

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

def screenshot_path(name: str) -> str:
    return os.path.join(CFG.screenshot_dir, f'{name}.png')

# ─── MUI Select Helpers ─────────────────────────────────────────────────────

async def find_select_id(page: Page, base_id: str) -> Optional[str]:
    """Find actual element ID, handling $ difference between DUT firmware versions."""
    return await page.evaluate('''(id) => {
        let el = document.getElementById(id);
        if (el) return id;
        const altId = id.replace(/\\$/g, '');
        el = document.getElementById(altId);
        if (el) return altId;
        return null;
    }''', base_id)

async def select_mui_option(page: Page, select_id: str, value: str) -> bool:
    actual_id = await find_select_id(page, select_id)
    if not actual_id:
        print(f'      WARNING: Element {select_id} not found')
        return False
    await page.evaluate('(id) => document.getElementById(id).scrollIntoView({block:"center"})', actual_id)
    await page.wait_for_timeout(300)
    escaped_id = actual_id.replace('$', '\\$').replace('.', '\\.')
    sel = page.locator(f'#{escaped_id}')
    await sel.click(timeout=5000)
    await page.wait_for_timeout(500)
    option = page.locator(f'[role="option"][data-value="{value}"]')
    if await option.count() > 0:
        await option.first.click()
        await page.wait_for_timeout(300)
        return True
    print(f'      WARNING: Option {value} not found')
    await page.keyboard.press('Escape')
    await page.wait_for_timeout(300)
    return False

async def select_dh_ikev1(page: Page, select_index: int, dh_value: str) -> bool:
    """Select DH group for IKEv1 Phase 1 (simple single-select dropdown at index 4)."""
    all_selects = page.locator('.MuiSelect-select')
    sel = all_selects.nth(select_index)
    await sel.scroll_into_view_if_needed()
    await sel.click(force=True)
    await page.wait_for_timeout(800)
    option = page.locator(f'[role="option"][data-value="{dh_value}"]')
    if await option.count() > 0:
        await option.first.click()
        await page.wait_for_timeout(300)
        return True
    print(f'      WARNING: DH {dh_value} not found')
    await page.keyboard.press('Escape')
    return False

async def select_user_defined(page: Page, select_id: str) -> bool:
    """Click a select and choose 'User Defined' to convert it to a text input."""
    actual_id = await find_select_id(page, select_id)
    if not actual_id:
        return False
    await page.evaluate('(id) => document.getElementById(id).scrollIntoView({block:"center"})', actual_id)
    await page.wait_for_timeout(300)
    escaped_id = actual_id.replace('$', '\\$').replace('.', '\\.')
    sel = page.locator(f'#{escaped_id}')
    await sel.click(timeout=5000)
    await page.wait_for_timeout(500)
    ud = page.locator('[role="option"][data-value="grid_add_new_rule"]')
    if await ud.count() > 0:
        await ud.first.click()
        await page.wait_for_timeout(500)
        return True
    await page.keyboard.press('Escape')
    return False

async def click_policy_add(page: Page) -> bool:
    """Click the Policy section's Add button (the toolbar with Add/Remove/Reference)."""
    return await page.evaluate('''() => {
        const containers = document.querySelectorAll('div, header');
        for (const container of containers) {
            const text = container.textContent?.trim() || '';
            const rect = container.getBoundingClientRect();
            if (text.startsWith('Add') && text.includes('Reference') &&
                rect.height > 20 && rect.height < 60 && rect.width > 200) {
                const addBtn = container.querySelector('button');
                if (addBtn) { addBtn.click(); return true; }
            }
        }
        return false;
    }''')

async def find_input_name(page: Page, candidates: List[str]) -> Optional[str]:
    """Find the first existing input by name from a list of candidates."""
    return await page.evaluate('''(names) => {
        for (const name of names) {
            const el = document.querySelector('input[name="' + name + '"]');
            if (el) return name;
        }
        return null;
    }''', candidates)

# ─── LAN Configuration ──────────────────────────────────────────────────────

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
    await click_btn(page, 'Apply')
    await page.wait_for_timeout(2000)
    await click_btn(page, 'OK', 5000)
    await page.wait_for_timeout(2000)
    await click_btn(page, 'Apply', 5000)
    await page.wait_for_timeout(5000)
    await click_btn(page, 'OK', 3000)
    await page.wait_for_timeout(3000)

# ─── Custom VPN Setup ───────────────────────────────────────────────────────

async def setup_custom_vpn(page: Page, dut: DUTConfig, peer_wan: str,
                           local_subnet: str, remote_subnet: str,
                           case: CustomVPNCase):
    print(f'\n=== Setting up Custom VPN on {dut.name}: {case.name} ===')
    await nav_to(page, 'VPN', 'IPSec VPN')
    await page.wait_for_timeout(2000)
    try:
        await page.locator('[role="tab"]').filter(has_text='Site to Site').first.click()
        await page.wait_for_timeout(2000)
    except Exception:
        pass

    # Remove existing VPN with same name
    existing = page.locator('tr').filter(has_text=case.name)
    if await existing.count() > 0:
        # Dismiss overlays first
        await page.evaluate('() => document.querySelectorAll(".MuiBackdrop-root").forEach(el => el.remove())')
        await page.wait_for_timeout(300)
        await click_btn(page, 'OK', 1000)
        await page.wait_for_timeout(300)
        await existing.first.locator('input[type="checkbox"]').first.click(force=True)
        await page.wait_for_timeout(500)
        await click_btn(page, 'Remove')
        await page.wait_for_timeout(2000)
        await click_btn(page, 'OK', 3000)
        await page.wait_for_timeout(2000)
        await click_btn(page, 'Apply', 5000)
        await page.wait_for_timeout(5000)
        await click_btn(page, 'OK', 3000)
        await page.wait_for_timeout(2000)

    # Step 1: Scenario - Custom
    await click_btn(page, 'Add')
    await page.wait_for_timeout(3000)
    print('  Step 1: Scenario (Custom)')
    await page.locator('#vpnwzdname').click()
    await page.locator('#vpnwzdname').fill(case.name)
    await page.locator('label').filter(has_text=re.compile(r'^Custom$')).click()
    await page.wait_for_timeout(500)
    await page.screenshot(path=screenshot_path(f'{dut.name}-{case.name}-S1'))
    await click_btn(page, 'Next')
    await page.wait_for_timeout(5000)

    # Step 2: General Settings (all on Custom single-page form)
    print('  Step 2: General Settings')
    # IKE Version
    await page.locator(f'input[name="vpn.version"][value="{case.ike_version}"]').click(force=True)
    await page.wait_for_timeout(1000)

    # VPN Type (Policy-based / Route-based)
    await page.locator(f'input[name="vpn.\\$type"][value="{case.vpn_type}"]').click(force=True)
    await page.wait_for_timeout(500)

    # Peer Gateway Address
    await page.locator('input[name="vpn.remote_gw"]').fill(peer_wan)

    # Pre-Shared Key
    await page.locator('input[name="preshkey.secret"]').fill(CFG.psk)

    print(f'    IKEv{case.ike_version}, {case.vpn_type}, Peer={peer_wan}')
    await page.screenshot(path=screenshot_path(f'{dut.name}-{case.name}-general'))

    # Step 3: Phase 1 Settings
    print('  Step 3: Phase 1 Settings')

    # IKEv1 uses P1ProposalGridv1, IKEv2 uses P1ProposalGrid
    if case.ike_version == '1':
        p1_enc_id = 'mui-component-select-P1ProposalGridv1_$proposal_enc_alg_select0'
        p1_auth_id = 'mui-component-select-P1ProposalGridv1_$proposal_auth_alg_select0'
    else:
        p1_enc_id = 'mui-component-select-P1ProposalGrid_$proposal_enc_alg_select0'
        p1_auth_id = 'mui-component-select-P1ProposalGrid_$proposal_auth_alg_select0'
    await select_mui_option(page, p1_enc_id, case.p1_enc)
    await select_mui_option(page, p1_auth_id, case.p1_auth)
    print(f'    Enc={case.p1_enc}, Auth={case.p1_auth}')
    # DH groups: keep defaults (DH2+DH14) — the multi-select chip component has no specific ID

    await page.screenshot(path=screenshot_path(f'{dut.name}-{case.name}-phase1'))

    # Step 4: Phase 2 Policy (Policy-based only)
    if case.vpn_type == 'Policy-based':
        print('  Step 4: Phase 2 Policy')
        await click_policy_add(page)
        await page.wait_for_timeout(2000)

        # Scroll to policy row
        await page.evaluate('''() => {
            const labels = document.querySelectorAll('label');
            for (const label of labels) {
                if (label.textContent?.trim() === 'Policy') {
                    label.scrollIntoView({ block: 'start' });
                    break;
                }
            }
        }''')
        await page.wait_for_timeout(500)

        # Local address - try User Defined
        local_select_candidates = [
            'mui-component-select-PolicyBasedPolicyGrid_$local_address_select0',
            'mui-component-select-NATruleGrid_$local_address_select0',
        ]
        for cand in local_select_candidates:
            if await select_user_defined(page, cand):
                break

        local_txt_name = await find_input_name(page, [
            'PolicyBasedPolicyGrid_$local_address_txt0',
            'PolicyBasedPolicyGrid_local_address_txt0',
            'NATruleGrid_$local_address_txt0',
            'NATruleGrid_local_address_txt0',
        ])
        if local_txt_name:
            await page.locator(f'input[name="{local_txt_name}"]').fill(local_subnet)
            print(f'    Local: {local_subnet}')

        # Remote address
        remote_select_candidates = [
            'mui-component-select-PolicyBasedPolicyGrid_$remote_address_select0',
            'mui-component-select-NATruleGrid_$remote_address_select0',
        ]
        for cand in remote_select_candidates:
            if await select_user_defined(page, cand):
                break

        remote_txt_name = await find_input_name(page, [
            'PolicyBasedPolicyGrid_$remote_address_txt0',
            'PolicyBasedPolicyGrid_remote_address_txt0',
            'NATruleGrid_$remote_address_txt0',
            'NATruleGrid_remote_address_txt0',
        ])
        if remote_txt_name:
            await page.locator(f'input[name="{remote_txt_name}"]').fill(remote_subnet)
            print(f'    Remote: {remote_subnet}')

        await page.screenshot(path=screenshot_path(f'{dut.name}-{case.name}-policy'))

    # Step 5: Phase 2 Proposal
    print('  Step 5: Phase 2 Proposal')
    p2_enc_id = 'mui-component-select-P2ProposalGrid_$proposal_enc_alg_select0'
    p2_auth_id = 'mui-component-select-P2ProposalGrid_$proposal_auth_alg_select0'
    await select_mui_option(page, p2_enc_id, case.p2_enc)
    # GCM encryption uses "Built-in" auth automatically; only set auth for non-GCM
    if 'gcm' not in case.p2_enc:
        await select_mui_option(page, p2_auth_id, case.p2_auth)
    print(f'    Enc={case.p2_enc}, Auth={case.p2_auth}')
    await page.screenshot(path=screenshot_path(f'{dut.name}-{case.name}-phase2'))

    # Step 6: Apply
    print('  Step 6: Apply')
    await page.evaluate('window.scrollTo(0, document.body.scrollHeight)')
    await page.wait_for_timeout(500)
    apply_btn = page.locator('button:has-text("Apply")').last
    await apply_btn.click()
    await page.wait_for_timeout(3000)
    await click_btn(page, 'OK', 5000)
    await page.wait_for_timeout(3000)
    await click_btn(page, 'Apply', 5000)
    await page.wait_for_timeout(5000)
    await click_btn(page, 'OK', 3000)
    await page.wait_for_timeout(2000)

    # Verify & Activate
    await nav_to(page, 'VPN', 'IPSec VPN')
    await page.wait_for_timeout(3000)
    try:
        await page.locator('[role="tab"]').filter(has_text='Site to Site').first.click()
        await page.wait_for_timeout(2000)
    except Exception:
        pass

    vpn_row = page.locator('tr').filter(has_text=case.name)
    if await vpn_row.count() > 0:
        print(f'  VPN "{case.name}" created!')
        await vpn_row.first.locator('input[type="checkbox"]').first.click()
        await page.wait_for_timeout(500)
        await click_btn(page, 'Active', 3000)
        await page.wait_for_timeout(2000)
        await click_btn(page, 'Connect', 3000)
        await page.wait_for_timeout(3000)
    else:
        print(f'  WARNING: VPN "{case.name}" not found')

    await page.screenshot(path=screenshot_path(f'{dut.name}-{case.name}-done'))

# ─── Remove VPN ─────────────────────────────────────────────────────────────

async def remove_vpn(page: Page, dut: DUTConfig, vpn_name: str):
    print(f'  Removing VPN {vpn_name} on {dut.name}...')
    await nav_to(page, 'VPN', 'IPSec VPN')
    await page.wait_for_timeout(3000)
    try:
        await page.locator('[role="tab"]').filter(has_text='Site to Site').first.click()
        await page.wait_for_timeout(2000)
    except Exception:
        pass

    await page.evaluate('() => document.querySelectorAll(".MuiBackdrop-root").forEach(el => el.remove())')
    await page.wait_for_timeout(300)
    await click_btn(page, 'OK', 1000)
    await page.wait_for_timeout(300)

    vpn_row = page.locator('tr').filter(has_text=vpn_name)
    if await vpn_row.count() > 0:
        await vpn_row.first.locator('input[type="checkbox"]').first.click(force=True)
        await page.wait_for_timeout(500)
        await click_btn(page, 'Remove')
        await page.wait_for_timeout(2000)
        await click_btn(page, 'OK', 3000)
        await page.wait_for_timeout(2000)
        await click_btn(page, 'Apply', 5000)
        await page.wait_for_timeout(5000)
        await click_btn(page, 'OK', 3000)
        await page.wait_for_timeout(2000)

async def restore_lan(page: Page, dut: DUTConfig, original_cidr: str):
    print(f'  Restoring {dut.name} ge3 LAN to {original_cidr}')
    await change_lan(page, dut, original_cidr)

# ─── Test Functions ──────────────────────────────────────────────────────────

def test_ping(src_mgmt: str, dst_ip: str, test_name: str, count: int = 4) -> TestResult:
    print(f'  {test_name}...')
    output = ssh(src_mgmt, f'ping -c {count} -W 3 {dst_ip} 2>&1')
    match = re.search(r'(\d+) received', output)
    received = int(match.group(1)) if match else 0
    match_rtt = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', output)
    avg_rtt = match_rtt.group(1) if match_rtt else 'N/A'
    passed = received > 0
    print(f'    {received}/{count} received, avg={avg_rtt}ms')
    return TestResult(name=test_name, passed=passed,
                      details=f'{received}/{count} packets, avg RTT={avg_rtt}ms', output=output)

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
    return TestResult(name=test_name, passed=passed, details=f'Bitrate: {bitrate}', output=output)

def test_mtu(src_mgmt: str, dst_ip: str, test_name: str, size: int = 1400) -> TestResult:
    print(f'  {test_name}...')
    output = ssh(src_mgmt, f'ping -c 4 -W 3 -s {size} -M do {dst_ip} 2>&1')
    match = re.search(r'(\d+) received', output)
    received = int(match.group(1)) if match else 0
    passed = received > 0
    print(f'    {received}/4 received with {size}B payload')
    return TestResult(name=test_name, passed=passed,
                      details=f'{received}/4 packets with {size}B payload', output=output)

# ─── Report Generation ──────────────────────────────────────────────────────

def generate_report(all_case_results: List[Tuple[CustomVPNCase, List[TestResult]]]) -> str:
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    sd = CFG.screenshot_dir

    total_tests = sum(len(results) for _, results in all_case_results)
    total_passed = sum(sum(1 for r in results if r.passed) for _, results in all_case_results)
    total_failed = total_tests - total_passed

    lines = []
    lines.append('# IPSec VPN Custom Configuration Test Report')
    lines.append('')
    lines.append(f'**Product**: Zyxel USG FLEX 500H / 700H')
    lines.append(f'**Test Date**: {now}')
    lines.append(f'**Test Mode**: Custom VPN Configuration (non-Wizard)')
    lines.append(f'**Overall Result**: {"PASS" if total_failed == 0 else "FAIL"} ({total_passed}/{total_tests} tests passed)')
    lines.append('')
    lines.append('---')
    lines.append('')

    # Environment
    lines.append('## 1. Test Environment')
    lines.append('')
    lines.append('```')
    lines.append(f'PC-B ({CFG.pc_b_lan}/24)          PC-C ({CFG.pc_c_lan}/24)')
    lines.append('        |                               |')
    lines.append('    [ge3 LAN]                       [ge3 LAN]')
    lines.append('   DUT-A (USG FLEX)              DUT-B (USG FLEX)')
    lines.append('    [ge1 WAN]                       [ge1 WAN]')
    lines.append(f'  {CFG.dut_a.wan_ip}  ──── WAN ────  {CFG.dut_b.wan_ip}')
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
    lines.append('---')
    lines.append('')

    # Test Cases Summary
    lines.append('## 2. Custom VPN Test Cases')
    lines.append('')
    lines.append('| # | Name | IKE | Encryption | Auth | DH | Result |')
    lines.append('|---|------|-----|-----------|------|----|--------|')
    for i, (case, results) in enumerate(all_case_results, 1):
        case_passed = all(r.passed for r in results)
        dh_str = case.p1_dh or 'Default'
        status = 'PASS' if case_passed else 'FAIL'
        lines.append(f'| {i} | {case.name} | IKEv{case.ike_version} | {case.p1_enc} | {case.p1_auth} | {dh_str} | {status} |')
    lines.append('')
    lines.append('---')
    lines.append('')

    # Detailed results per case
    test_counter = 0
    for i, (case, results) in enumerate(all_case_results, 1):
        case_passed = all(r.passed for r in results)
        lines.append(f'## 3.{i} Test Case {i}: {case.description}')
        lines.append('')
        lines.append(f'**VPN Name**: {case.name}')
        lines.append(f'**IKE Version**: IKEv{case.ike_version}')
        lines.append(f'**Phase 1**: Encryption={case.p1_enc}, Auth={case.p1_auth}, DH={case.p1_dh or "Default"}')
        lines.append(f'**Phase 2**: Encryption={case.p2_enc}, Auth={case.p2_auth}')
        lines.append(f'**Result**: {"PASS" if case_passed else "FAIL"}')
        lines.append('')

        # Configuration screenshots
        lines.append('### Configuration')
        lines.append('')
        for dut_name in ['DUT-A', 'DUT-B']:
            lines.append(f'**{dut_name}**')
            lines.append('')
            for step in ['general', 'phase1', 'policy', 'phase2', 'done']:
                img = f'{sd}/{dut_name}-{case.name}-{step}.png'
                if os.path.exists(img):
                    lines.append(f'![{dut_name} {step}]({img})')
                    lines.append('')
        lines.append('')

        # Test results table
        lines.append('### Connectivity Tests')
        lines.append('')
        lines.append('| # | Test | Result | Details |')
        lines.append('|---|------|:------:|---------|')
        for r in results:
            test_counter += 1
            status = 'PASS' if r.passed else 'FAIL'
            lines.append(f'| {test_counter} | {r.name} | {status} | {r.details} |')
        lines.append('')

        # Full output
        lines.append('### Detailed Output')
        lines.append('')
        for r in results:
            status = 'PASS' if r.passed else 'FAIL'
            lines.append(f'#### {r.name} [{status}]')
            lines.append('')
            lines.append('```')
            lines.append(r.output)
            lines.append('```')
            lines.append('')

        lines.append('---')
        lines.append('')

    # Overall Summary
    lines.append('## 4. Overall Summary')
    lines.append('')
    lines.append('| Test Case | Tests | Passed | Failed | Status |')
    lines.append('|-----------|:-----:|:------:|:------:|:------:|')
    for i, (case, results) in enumerate(all_case_results, 1):
        cp = sum(1 for r in results if r.passed)
        cf = len(results) - cp
        status = 'PASS' if cf == 0 else 'FAIL'
        lines.append(f'| {case.name} | {len(results)} | {cp} | {cf} | {status} |')
    lines.append(f'| **Total** | **{total_tests}** | **{total_passed}** | **{total_failed}** | **{"PASS" if total_failed == 0 else "FAIL"}** |')
    lines.append('')

    return '\n'.join(lines)

# ─── Main ────────────────────────────────────────────────────────────────────

async def main():
    os.makedirs(CFG.screenshot_dir, exist_ok=True)

    print('=' * 60)
    print('IPSec VPN Custom Configuration Automated Test')
    print(f'{len(CUSTOM_CASES)} test cases')
    print('=' * 60)

    all_case_results: List[Tuple[CustomVPNCase, List[TestResult]]] = []

    async with async_playwright() as p:
        # ── Phase 1: Configure LAN subnets (once) ──
        print('\n--- Phase 1: LAN Subnet Configuration ---')
        for dut, cidr in [(CFG.dut_a, '192.168.1.1/24'), (CFG.dut_b, '192.168.2.1/24')]:
            browser = await p.chromium.launch(headless=CFG.headless)
            page = await browser.new_page(ignore_https_errors=True)
            page.set_default_timeout(30000)
            await login(page, dut.mgmt_ip)
            await change_lan(page, dut, cidr)
            await browser.close()

        print('\n  Waiting 10s for LAN changes...')
        await asyncio.sleep(10)

        # DHCP renew
        print('  Renewing DHCP on PCs...')
        ssh(CFG.pc_b_mgmt, f'echo {CFG.pc_pass} | sudo -S networkctl reconfigure enp2s0 2>/dev/null')
        ssh(CFG.pc_c_mgmt, f'echo {CFG.pc_pass} | sudo -S networkctl reconfigure enp2s0 2>/dev/null')
        await asyncio.sleep(5)

        pc_b_ip = ssh(CFG.pc_b_mgmt, "ip -4 addr show enp2s0 | grep 'inet ' | awk '{print $2}'")
        pc_c_ip = ssh(CFG.pc_c_mgmt, "ip -4 addr show enp2s0 | grep 'inet ' | awk '{print $2}'")
        if pc_b_ip and '/' in pc_b_ip:
            CFG.pc_b_lan = pc_b_ip.split('/')[0]
        if pc_c_ip and '/' in pc_c_ip:
            CFG.pc_c_lan = pc_c_ip.split('/')[0]
        print(f'  PC-B: {CFG.pc_b_lan}, PC-C: {CFG.pc_c_lan}')

        # ── Phase 2: Run each Custom VPN test case ──
        for case_idx, case in enumerate(CUSTOM_CASES, 1):
            print(f'\n{"=" * 60}')
            print(f'Test Case {case_idx}/{len(CUSTOM_CASES)}: {case.description}')
            print(f'{"=" * 60}')

            # Configure VPN on both DUTs
            for dut, peer_wan, local_sub, remote_sub in [
                (CFG.dut_a, CFG.dut_b.wan_ip, CFG.dut_a.lan_subnet, CFG.dut_b.lan_subnet),
                (CFG.dut_b, CFG.dut_a.wan_ip, CFG.dut_b.lan_subnet, CFG.dut_a.lan_subnet),
            ]:
                browser = await p.chromium.launch(headless=CFG.headless)
                page = await browser.new_page(ignore_https_errors=True)
                page.set_default_timeout(30000)
                await login(page, dut.mgmt_ip)
                await setup_custom_vpn(page, dut, peer_wan, local_sub, remote_sub, case)
                await browser.close()

            print('\n  Waiting 15s for VPN tunnel...')
            await asyncio.sleep(15)

            # Run connectivity tests
            print('\n--- Connectivity Tests ---')
            case_results: List[TestResult] = []

            case_results.append(test_ping(CFG.pc_b_mgmt, CFG.dut_b.lan_gateway,
                                          f'PC-B -> DUT-B LAN GW ({CFG.dut_b.lan_gateway})'))
            case_results.append(test_ping(CFG.pc_c_mgmt, CFG.dut_a.lan_gateway,
                                          f'PC-C -> DUT-A LAN GW ({CFG.dut_a.lan_gateway})'))
            case_results.append(test_ping(CFG.pc_b_mgmt, CFG.pc_c_lan,
                                          f'PC-B -> PC-C ({CFG.pc_c_lan})'))
            case_results.append(test_ping(CFG.pc_c_mgmt, CFG.pc_b_lan,
                                          f'PC-C -> PC-B ({CFG.pc_b_lan})'))
            case_results.append(test_iperf3(CFG.pc_b_mgmt, CFG.pc_c_lan, CFG.pc_c_mgmt,
                                            f'iperf3 PC-B -> PC-C'))
            case_results.append(test_mtu(CFG.pc_b_mgmt, CFG.pc_c_lan,
                                         f'MTU 1400B DF-bit'))

            cp = sum(1 for r in case_results if r.passed)
            cf = len(case_results) - cp
            print(f'\n  Case Result: {cp}/{len(case_results)} passed {"PASS" if cf == 0 else "FAIL"}')
            all_case_results.append((case, case_results))

            # Remove VPN before next test case
            print('\n--- Removing VPN ---')
            for dut in [CFG.dut_a, CFG.dut_b]:
                browser = await p.chromium.launch(headless=CFG.headless)
                page = await browser.new_page(ignore_https_errors=True)
                page.set_default_timeout(30000)
                await login(page, dut.mgmt_ip)
                await remove_vpn(page, dut, case.name)
                await browser.close()

            await asyncio.sleep(3)

    # ── Phase 3: Generate Report ──
    print('\n--- Phase 3: Generating Report ---')
    report = generate_report(all_case_results)
    report_path = 'IPSec_Custom_VPN_Test_Report.md'
    with open(report_path, 'w') as f:
        f.write(report)
    print(f'Report saved to {report_path}')

    total_tests = sum(len(r) for _, r in all_case_results)
    total_passed = sum(sum(1 for t in r if t.passed) for _, r in all_case_results)
    total_failed = total_tests - total_passed
    print(f'\nTotal: {total_tests} tests, {total_passed} passed, {total_failed} failed')
    print(f'Overall: {"PASS" if total_failed == 0 else "FAIL"}')

    # ── Phase 4: Restore DUT Configuration ──
    print('\n--- Phase 4: Restoring DUT Configuration ---')
    async with async_playwright() as p:
        for dut in [CFG.dut_a, CFG.dut_b]:
            browser = await p.chromium.launch(headless=CFG.headless)
            page = await browser.new_page(ignore_https_errors=True)
            page.set_default_timeout(30000)
            await login(page, dut.mgmt_ip)
            await restore_lan(page, dut, CFG.default_lan_cidr)
            await browser.close()

        print('\n  Waiting 10s for changes...')
        await asyncio.sleep(10)
        ssh(CFG.pc_b_mgmt, f'echo {CFG.pc_pass} | sudo -S networkctl reconfigure enp2s0 2>/dev/null')
        ssh(CFG.pc_c_mgmt, f'echo {CFG.pc_pass} | sudo -S networkctl reconfigure enp2s0 2>/dev/null')
        await asyncio.sleep(5)
        print('  DUT configuration restored.')

    return 0 if total_failed == 0 else 1

if __name__ == '__main__':
    sys.exit(asyncio.run(main()))
