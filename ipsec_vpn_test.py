#!/usr/bin/env python3
"""
IPSec Site-to-Site VPN Automated Test Suite
Product: Zyxel USG FLEX 500H / 700H

Subcommands:
    wizard  - VPN Wizard (IKEv2 Policy-Based) test
    custom  - Custom VPN test (5 IKEv1/IKEv2 combinations)
    all     - Run both wizard and custom tests sequentially

Usage:
    ./run.sh wizard
    ./run.sh custom
    ./run.sh all
"""

import argparse
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

# ─── PyInstaller Support ────────────────────────────────────────────────────

def _get_base_dir():
    # type: () -> str
    """Return the directory where the executable (or script) resides."""
    if getattr(sys, 'frozen', False):
        # PyInstaller --onedir: sys.executable is inside dist/ipsec_vpn_test/
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def _setup_playwright_env():
    """Set PLAYWRIGHT_BROWSERS_PATH if running from PyInstaller bundle."""
    if not getattr(sys, 'frozen', False):
        return
    # PyInstaller --onedir: _internal/ is at sys._MEIPASS
    bundle_dir = sys._MEIPASS  # type: ignore[attr-defined]
    browsers_dir = os.path.join(bundle_dir, 'ms-playwright')
    if os.path.isdir(browsers_dir):
        os.environ['PLAYWRIGHT_BROWSERS_PATH'] = browsers_dir


_setup_playwright_env()

# ─── Configuration ───────────────────────────────────────────────────────────

CONFIG_FILE = os.path.join(_get_base_dir(), 'config.yaml')


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


def load_config(path=CONFIG_FILE):
    # type: (str) -> TestConfig
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


# Lazy-loaded: initialized by init_cfg() at test start, so --help works without config.yaml
CFG = None  # type: Optional[TestConfig]


def init_cfg():
    # type: () -> None
    global CFG
    if CFG is None:
        CFG = load_config()

# ─── Custom VPN Test Cases ──────────────────────────────────────────────────


@dataclass
class CustomVPNCase:
    name: str
    ike_version: str       # "1" or "2"
    vpn_type: str          # "Policy-based" or "Route-based"
    p1_enc: str
    p1_auth: str
    p1_dh: Optional[str]   # DH group; None = use defaults
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

def ssh(host, cmd, timeout=30):
    # type: (str, str, int) -> str
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

async def login(page, ip):
    # type: (Page, str) -> None
    await page.goto(f'https://{ip}', timeout=30000)
    await page.wait_for_timeout(3000)
    await page.locator('input').first.fill(CFG.dut_user)
    await page.locator('input').nth(1).fill(CFG.dut_pass)
    await page.locator('button:has-text("Login")').click()
    await page.wait_for_timeout(5000)


async def nav_to(page, parent, child):
    # type: (Page, str, str) -> None
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


async def click_btn(page, text, timeout=5000):
    # type: (Page, str, int) -> bool
    try:
        btn = page.locator(f'button:has-text("{text}")')
        for i in range(await btn.count()):
            if await btn.nth(i).is_visible(timeout=timeout):
                await btn.nth(i).click()
                return True
    except Exception:
        pass
    return False


def screenshot_path(name):
    # type: (str) -> str
    sd = CFG.screenshot_dir
    if not os.path.isabs(sd):
        sd = os.path.join(_get_base_dir(), sd)
    return os.path.join(sd, f'{name}.png')


# ─── LAN Configuration ──────────────────────────────────────────────────────

async def change_lan(page, dut, new_cidr):
    # type: (Page, DUTConfig, str) -> None
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


# ─── MUI Select Helpers (Custom VPN) ──────────────────────────────────────

async def find_select_id(page, base_id):
    # type: (Page, str) -> Optional[str]
    return await page.evaluate('''(id) => {
        let el = document.getElementById(id);
        if (el) return id;
        const altId = id.replace(/\\$/g, '');
        el = document.getElementById(altId);
        if (el) return altId;
        return null;
    }''', base_id)


async def select_mui_option(page, select_id, value):
    # type: (Page, str, str) -> bool
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


async def select_user_defined(page, select_id):
    # type: (Page, str) -> bool
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


async def click_policy_add(page):
    # type: (Page,) -> bool
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


async def find_input_name(page, candidates):
    # type: (Page, List[str]) -> Optional[str]
    return await page.evaluate('''(names) => {
        for (const name of names) {
            const el = document.querySelector('input[name="' + name + '"]');
            if (el) return name;
        }
        return null;
    }''', candidates)


# ─── Wizard VPN Helpers ──────────────────────────────────────────────────────

async def get_form_inputs(page):
    # type: (Page,) -> List[dict]
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


# ═══════════════════════════════════════════════════════════════════════════════
# Wizard VPN Setup
# ═══════════════════════════════════════════════════════════════════════════════

async def setup_wizard_vpn(page, dut, peer_wan, local_subnet, remote_subnet):
    # type: (Page, DUTConfig, str, str, str) -> None
    print(f'\n=== Setting up IPSec VPN on {dut.name} (Wizard) ===')
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
    await nav_to(page, 'Monitor', 'IPSec')
    await page.wait_for_timeout(3000)
    await page.screenshot(path=screenshot_path(f'{dut.name}-monitor-ipsec'))


# ═══════════════════════════════════════════════════════════════════════════════
# Custom VPN Setup
# ═══════════════════════════════════════════════════════════════════════════════

async def setup_custom_vpn(page, dut, peer_wan, local_subnet, remote_subnet, case):
    # type: (Page, DUTConfig, str, str, str, CustomVPNCase) -> None
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

    # Step 2: General Settings
    print('  Step 2: General Settings')
    await page.locator(f'input[name="vpn.version"][value="{case.ike_version}"]').click(force=True)
    await page.wait_for_timeout(1000)
    await page.locator(f'input[name="vpn.\\$type"][value="{case.vpn_type}"]').click(force=True)
    await page.wait_for_timeout(500)
    await page.locator('input[name="vpn.remote_gw"]').fill(peer_wan)
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
    await page.screenshot(path=screenshot_path(f'{dut.name}-{case.name}-phase1'))

    # Step 4: Phase 2 Policy (Policy-based only)
    if case.vpn_type == 'Policy-based':
        print('  Step 4: Phase 2 Policy')
        await click_policy_add(page)
        await page.wait_for_timeout(2000)
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

        # Local address
        for cand in [
            'mui-component-select-PolicyBasedPolicyGrid_$local_address_select0',
            'mui-component-select-NATruleGrid_$local_address_select0',
        ]:
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
        for cand in [
            'mui-component-select-PolicyBasedPolicyGrid_$remote_address_select0',
            'mui-component-select-NATruleGrid_$remote_address_select0',
        ]:
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


# ═══════════════════════════════════════════════════════════════════════════════
# Remove VPN / Restore LAN
# ═══════════════════════════════════════════════════════════════════════════════

async def remove_vpn(page, dut, vpn_name):
    # type: (Page, DUTConfig, str) -> None
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
    else:
        print(f'    No VPN entry "{vpn_name}" found on {dut.name}')


# ─── Test Functions ──────────────────────────────────────────────────────────

def test_ping(src_mgmt, dst_ip, test_name, count=4):
    # type: (str, str, str, int) -> TestResult
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


def test_iperf3(src_mgmt, dst_ip, server_mgmt, test_name, duration=10):
    # type: (str, str, str, str, int) -> TestResult
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


def test_traceroute(src_mgmt, dst_ip, test_name):
    # type: (str, str, str) -> TestResult
    print(f'  {test_name}...')
    output = ssh(src_mgmt, f'traceroute -n -w 3 -m 5 {dst_ip} 2>&1')
    print(f'    {output}')
    hop_lines = [l for l in output.splitlines() if re.match(r'\s*\d+\s', l)]
    passed = len(hop_lines) >= 2 and dst_ip in output
    return TestResult(name=test_name, passed=passed, details=f'{len(hop_lines)} hops', output=output)


def test_mtu(src_mgmt, dst_ip, test_name, size=1400):
    # type: (str, str, str, int) -> TestResult
    print(f'  {test_name}...')
    output = ssh(src_mgmt, f'ping -c 4 -W 3 -s {size} -M do {dst_ip} 2>&1')
    match = re.search(r'(\d+) received', output)
    received = int(match.group(1)) if match else 0
    passed = received > 0
    print(f'    {received}/4 received with {size}B payload')
    return TestResult(name=test_name, passed=passed,
                      details=f'{received}/4 packets with {size}B payload', output=output)


def test_tcp(src_mgmt, dst_ip, server_mgmt, test_name):
    # type: (str, str, str, str) -> TestResult
    print(f'  {test_name}...')
    ssh(server_mgmt, 'echo "VPN_TUNNEL_OK" | nc -l -p 9999 -w 5 &')
    time.sleep(1)
    output = ssh(src_mgmt, f'echo "HELLO" | nc -w 3 {dst_ip} 9999 2>&1')
    print(f'    Response: {output}')
    passed = 'VPN_TUNNEL_OK' in output
    return TestResult(name=test_name, passed=passed, details=f'Response: {output}', output=output)


# ─── Common Phases ───────────────────────────────────────────────────────────

async def phase_setup_lan(p):
    """Phase: Configure LAN subnets on both DUTs and renew DHCP."""
    print('\n--- LAN Subnet Configuration ---')
    for dut, cidr in [(CFG.dut_a, '192.168.1.1/24'), (CFG.dut_b, '192.168.2.1/24')]:
        browser = await p.chromium.launch(headless=CFG.headless)
        page = await browser.new_page(ignore_https_errors=True)
        page.set_default_timeout(30000)
        await login(page, dut.mgmt_ip)
        await change_lan(page, dut, cidr)
        await browser.close()

    print('\n  Waiting 10s for LAN changes...')
    await asyncio.sleep(10)
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


async def phase_restore(p):
    """Phase: Restore DUT LAN configuration to defaults."""
    print('\n--- Restoring DUT Configuration ---')
    for dut in [CFG.dut_a, CFG.dut_b]:
        browser = await p.chromium.launch(headless=CFG.headless)
        page = await browser.new_page(ignore_https_errors=True)
        page.set_default_timeout(30000)
        await login(page, dut.mgmt_ip)
        print(f'  Restoring {dut.name} ge3 LAN to {CFG.default_lan_cidr}')
        await change_lan(page, dut, CFG.default_lan_cidr)
        await browser.close()
    print('\n  Waiting 10s for changes...')
    await asyncio.sleep(10)
    ssh(CFG.pc_b_mgmt, f'echo {CFG.pc_pass} | sudo -S networkctl reconfigure enp2s0 2>/dev/null')
    ssh(CFG.pc_c_mgmt, f'echo {CFG.pc_pass} | sudo -S networkctl reconfigure enp2s0 2>/dev/null')
    await asyncio.sleep(5)
    print('  DUT configuration restored.')


# ═══════════════════════════════════════════════════════════════════════════════
# Report Generation — Wizard
# ═══════════════════════════════════════════════════════════════════════════════

def generate_wizard_report(test_results):
    # type: (List[TestResult]) -> str
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

    lines.append('## 2. LAN Subnet Configuration')
    lines.append('')
    for dn in ['DUT-A', 'DUT-B']:
        lines.append(f'### {dn}')
        lines.append('')
        for step in ['lan-edit', 'lan-done']:
            img = f'{sd}/{dn}-{step}.png'
            if os.path.exists(img):
                lines.append(f'![{dn} {step}]({img})')
                lines.append('')
    lines.append('---')
    lines.append('')

    lines.append('## 3. VPN Configuration (Wizard)')
    lines.append('')
    for dut_name, peer in [('DUT-A', CFG.dut_b.wan_ip), ('DUT-B', CFG.dut_a.wan_ip)]:
        lines.append(f'### {dut_name}')
        lines.append('')
        for step, desc in [('S1', 'Scenario'), ('S2', 'Network'), ('S3', 'Authentication'),
                           ('S4', 'Policy & Routing'), ('S5', 'Summary')]:
            img = f'{sd}/{dut_name}-{step}.png'
            if os.path.exists(img):
                lines.append(f'**Step: {desc}**')
                lines.append('')
                lines.append(f'![{dut_name} {step}]({img})')
                lines.append('')
    lines.append('### VPN Status')
    lines.append('')
    for dn in ['DUT-A', 'DUT-B']:
        for step in ['vpn-status', 'monitor-ipsec']:
            img = f'{sd}/{dn}-{step}.png'
            if os.path.exists(img):
                lines.append(f'![{dn} {step}]({img})')
                lines.append('')
    lines.append('---')
    lines.append('')

    lines.append('## 4. Test Results')
    lines.append('')
    lines.append('| # | Test | Result | Details |')
    lines.append('|---|------|:------:|---------|')
    for i, r in enumerate(test_results, 1):
        status = 'PASS' if r.passed else 'FAIL'
        lines.append(f'| {i} | {r.name} | {status} | {r.details} |')
    lines.append('')

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

    lines.append('## 5. Overall Summary')
    lines.append('')
    lines.append(f'| Total | Passed | Failed | Result |')
    lines.append(f'|:-----:|:------:|:------:|:------:|')
    lines.append(f'| {total} | {passed} | {failed} | {"PASS" if failed == 0 else "FAIL"} |')
    lines.append('')

    return '\n'.join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# Report Generation — Custom
# ═══════════════════════════════════════════════════════════════════════════════

def generate_custom_report(all_case_results):
    # type: (List[Tuple[CustomVPNCase, List[TestResult]]]) -> str
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

        lines.append('### Connectivity Tests')
        lines.append('')
        lines.append('| # | Test | Result | Details |')
        lines.append('|---|------|:------:|---------|')
        for r in results:
            test_counter += 1
            status = 'PASS' if r.passed else 'FAIL'
            lines.append(f'| {test_counter} | {r.name} | {status} | {r.details} |')
        lines.append('')

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


# ═══════════════════════════════════════════════════════════════════════════════
# Main — Wizard
# ═══════════════════════════════════════════════════════════════════════════════

async def main_wizard():
    # type: () -> int
    init_cfg()
    sd = CFG.screenshot_dir
    if not os.path.isabs(sd):
        sd = os.path.join(_get_base_dir(), sd)
    os.makedirs(sd, exist_ok=True)

    print('=' * 60)
    print('IPSec Site-to-Site VPN Automated Test — Wizard Mode')
    print('=' * 60)

    results = []  # type: List[TestResult]

    async with async_playwright() as p:
        await phase_setup_lan(p)

        # Configure VPN via Wizard
        print('\n--- VPN Configuration (Wizard) ---')
        for dut, peer_wan, local_sub, remote_sub in [
            (CFG.dut_a, CFG.dut_b.wan_ip, CFG.dut_a.lan_subnet, CFG.dut_b.lan_subnet),
            (CFG.dut_b, CFG.dut_a.wan_ip, CFG.dut_b.lan_subnet, CFG.dut_a.lan_subnet),
        ]:
            browser = await p.chromium.launch(headless=CFG.headless)
            page = await browser.new_page(ignore_https_errors=True)
            page.set_default_timeout(20000)
            await login(page, dut.mgmt_ip)
            await setup_wizard_vpn(page, dut, peer_wan, local_sub, remote_sub)
            await browser.close()

        print('\n  Waiting 15s for VPN tunnel...')
        await asyncio.sleep(15)

    # Connectivity Tests
    print('\n--- Connectivity Tests ---')
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

    # Report
    print('\n--- Generating Report ---')
    report = generate_wizard_report(results)
    report_path = os.path.join(_get_base_dir(), 'IPSec_VPN_Test_Report.md')
    with open(report_path, 'w') as f:
        f.write(report)
    print(f'Report saved to {report_path}')

    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed
    print(f'\nTotal: {len(results)} tests, {passed} passed, {failed} failed')
    print(f'Overall: {"PASS" if failed == 0 else "FAIL"}')

    # Restore
    async with async_playwright() as p:
        for dut in [CFG.dut_a, CFG.dut_b]:
            browser = await p.chromium.launch(headless=CFG.headless)
            page = await browser.new_page(ignore_https_errors=True)
            page.set_default_timeout(20000)
            await login(page, dut.mgmt_ip)
            await remove_vpn(page, dut, CFG.vpn_name)
            await browser.close()
        await phase_restore(p)

    return 0 if failed == 0 else 1


# ═══════════════════════════════════════════════════════════════════════════════
# Main — Custom
# ═══════════════════════════════════════════════════════════════════════════════

async def main_custom():
    # type: () -> int
    init_cfg()
    sd = CFG.screenshot_dir
    if not os.path.isabs(sd):
        sd = os.path.join(_get_base_dir(), sd)
    os.makedirs(sd, exist_ok=True)

    print('=' * 60)
    print('IPSec VPN Custom Configuration Automated Test')
    print(f'{len(CUSTOM_CASES)} test cases')
    print('=' * 60)

    all_case_results = []  # type: List[Tuple[CustomVPNCase, List[TestResult]]]

    async with async_playwright() as p:
        await phase_setup_lan(p)

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

            # Connectivity tests
            print('\n--- Connectivity Tests ---')
            case_results = []  # type: List[TestResult]
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

            # Remove VPN
            print('\n--- Removing VPN ---')
            for dut in [CFG.dut_a, CFG.dut_b]:
                browser = await p.chromium.launch(headless=CFG.headless)
                page = await browser.new_page(ignore_https_errors=True)
                page.set_default_timeout(30000)
                await login(page, dut.mgmt_ip)
                await remove_vpn(page, dut, case.name)
                await browser.close()
            await asyncio.sleep(3)

    # Report
    print('\n--- Generating Report ---')
    report = generate_custom_report(all_case_results)
    report_path = os.path.join(_get_base_dir(), 'IPSec_Custom_VPN_Test_Report.md')
    with open(report_path, 'w') as f:
        f.write(report)
    print(f'Report saved to {report_path}')

    total_tests = sum(len(r) for _, r in all_case_results)
    total_passed = sum(sum(1 for t in r if t.passed) for _, r in all_case_results)
    total_failed = total_tests - total_passed
    print(f'\nTotal: {total_tests} tests, {total_passed} passed, {total_failed} failed')
    print(f'Overall: {"PASS" if total_failed == 0 else "FAIL"}')

    # Restore
    async with async_playwright() as p:
        await phase_restore(p)

    return 0 if total_failed == 0 else 1


# ═══════════════════════════════════════════════════════════════════════════════
# Main — All
# ═══════════════════════════════════════════════════════════════════════════════

async def main_all():
    # type: () -> int
    r1 = await main_wizard()
    r2 = await main_custom()
    return 0 if (r1 == 0 and r2 == 0) else 1


# ═══════════════════════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='IPSec Site-to-Site VPN Automated Test Suite for Zyxel USG FLEX 500H/700H',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''\
Examples:
  %(prog)s wizard    Run Wizard VPN test (IKEv2 Policy-Based)
  %(prog)s custom    Run Custom VPN tests (5 IKEv1/IKEv2 combinations)
  %(prog)s all       Run both wizard and custom tests
''')
    parser.add_argument('mode', choices=['wizard', 'custom', 'all'],
                        help='Test mode: wizard, custom, or all')
    args = parser.parse_args()

    if args.mode == 'wizard':
        sys.exit(asyncio.run(main_wizard()))
    elif args.mode == 'custom':
        sys.exit(asyncio.run(main_custom()))
    else:
        sys.exit(asyncio.run(main_all()))


if __name__ == '__main__':
    main()
