# IPSec Site-to-Site VPN Automated Test

Zyxel USG FLEX 500H / 700H 產品的 IPSec Site-to-Site VPN 自動化測試腳本。透過 Playwright 操作 DUT Web UI 完成 VPN 設定，並透過 SSH 在測試 PC 上執行網路驗證工具，最終產生含截圖與完整測試輸出的 Markdown 報告。

## 網路拓撲

```
PC-B (LAN)                              PC-C (LAN)
    |                                       |
 [ge3 LAN]                              [ge3 LAN]
DUT-A (USG FLEX 500H)              DUT-B (USG FLEX 500H)
 [ge1 WAN]                              [ge1 WAN]
    |____________ IPSec Tunnel ______________|
```

## 測試項目

| 類別 | 測試工具 | 說明 |
|------|---------|------|
| ICMP 連通性 | `ping` | 雙向跨隧道 ping（PC-B ↔ PC-C、PC ↔ 對端 DUT LAN gateway） |
| 吞吐量 | `iperf3` | 雙向 TCP 吞吐量（10 秒） |
| 路由驗證 | `traceroute` | 確認流量經過 IPSec 隧道（3 跳） |
| MTU 測試 | `ping -s 1400 -M do` | 1400B payload + DF bit，驗證無分片問題 |
| TCP 連線 | `netcat (nc)` | 跨隧道 TCP 連線驗證 |

## 自動化流程

```
Phase 1: 設定 LAN 子網（ge3 介面）
Phase 2: 透過 VPN Wizard 設定 IPSec Site-to-Site VPN（IKEv2, Policy-Based）
Phase 3: 執行連通性測試（ping, iperf3, traceroute, MTU, TCP）
Phase 4: 產生 Markdown 測試報告（含截圖與完整工具輸出）
Phase 5: 復原 DUT 設定（移除 VPN、還原 ge3 LAN IP）
```

## 環境需求

### 控制端（執行腳本的機器）

- Python 3.10+
- 套件：`playwright`, `pyyaml`
- `sshpass`（用於 SSH 自動登入測試 PC）

### 測試 PC（PC-B, PC-C）

- Ubuntu Linux
- 已安裝：`ping`, `traceroute`, `iperf3`, `netcat (nc)`
- 透過 DHCP 從 DUT 取得 LAN IP
- 管理介面（獨立網段）可供 SSH 連線

### DUT（Device Under Test）

- Zyxel USG FLEX 500H / 700H
- Web UI 可透過管理 IP 存取（HTTPS）
- ge1 為 WAN 介面，ge3 為 LAN 介面

## 快速開始

### 1. 安裝相依套件

```bash
pip install playwright pyyaml
playwright install chromium
```

macOS 安裝 sshpass：

```bash
brew install hudochenkov/sshpass/sshpass
```

### 2. 設定參數檔

```bash
cp config.yaml.example config.yaml
```

編輯 `config.yaml`，填入實際的 IP 位址與帳密：

```yaml
# DUT 登入帳密
dut_user: "admin"
dut_pass: "your_dut_password"

# 測試 PC SSH 帳密
pc_user: "testuser"
pc_pass: "your_pc_password"

# VPN 設定
vpn_name: "S2S_Test"
psk: "YourPreSharedKey"

# DUT-A
dut_a:
  name: "DUT-A"
  mgmt_ip: "192.168.121.x"
  wan_ip: "192.168.111.x"
  lan_subnet: "192.168.1.0/24"
  lan_gateway: "192.168.1.1"

# DUT-B
dut_b:
  name: "DUT-B"
  mgmt_ip: "192.168.121.x"
  wan_ip: "192.168.111.x"
  lan_subnet: "192.168.2.0/24"
  lan_gateway: "192.168.2.1"

# PC-B（DUT-A 後端測試 PC）
pc_b:
  mgmt_ip: "192.168.121.x"
  lan_ip: "192.168.1.x"

# PC-C（DUT-B 後端測試 PC）
pc_c:
  mgmt_ip: "192.168.121.x"
  lan_ip: "192.168.2.x"

# 測試選項
headless: false
screenshot_dir: "screenshots"
default_lan_cidr: "192.168.168.1/24"
```

> `pc_b.lan_ip` / `pc_c.lan_ip` 為預期值，腳本會在 DHCP 更新後自動偵測實際 IP。

### 3. 執行測試

```bash
python ipsec_vpn_test.py
```

腳本會：
1. 開啟瀏覽器視窗操作兩台 DUT 的 Web UI
2. 設定 LAN 子網與 IPSec VPN
3. 透過 SSH 在 PC-B / PC-C 執行測試工具
4. 產生 `IPSec_VPN_Test_Report.md` 報告
5. 測試完畢後自動復原 DUT 設定

### 4. 執行 Custom VPN 測試（Phase 2）

```bash
python ipsec_custom_vpn_test.py
```

腳本會：
1. 設定 LAN 子網
2. 依序執行 5 組 Custom VPN 設定（IKEv1/IKEv2 + 不同加密/驗證組合）
3. 每組設定完成後執行連通性測試（ping, iperf3, MTU）
4. 測試完畢移除該 VPN，再進行下一組
5. 產生 `IPSec_Custom_VPN_Test_Report.md` 報告
6. 復原 DUT 設定

### Custom VPN 測試案例

| # | 名稱 | IKE | 加密 | 驗證 | DH |
|---|------|-----|------|------|----|
| 1 | IKEv2_AES256_SHA256 | IKEv2 | AES256-CBC | SHA256 | Default |
| 2 | IKEv2_AES128GCM_SHA512 | IKEv2 | AES128-GCM | SHA512 | Default |
| 3 | IKEv1_AES256_SHA256 | IKEv1 | AES256-CBC | SHA256 | Default |
| 4 | IKEv1_3DES_SHA1 | IKEv1 | 3DES | SHA1 | Default |
| 5 | IKEv2_AES256GCM_SHA384 | IKEv2 | AES256-GCM | SHA384 | Default |

## 輸出檔案

| 檔案 | 說明 |
|------|------|
| `IPSec_VPN_Test_Report.md` | Wizard VPN 測試報告 |
| `IPSec_Custom_VPN_Test_Report.md` | Custom VPN 測試報告（5 組設定） |
| `screenshots/*.png` | 所有 Web UI 操作截圖與狀態頁面 |

## 專案結構

```
ipsec-vpn-test/
├── ipsec_vpn_test.py              # Wizard VPN 測試腳本
├── ipsec_custom_vpn_test.py       # Custom VPN 測試腳本（5 組設定）
├── config.yaml.example            # 參數檔範本（釋出用）
├── config.yaml                    # 實際參數檔（不納入版控）
├── .gitignore
├── README.md
├── screenshots/
├── IPSec_VPN_Test_Report.md       # Wizard VPN 測試報告
└── IPSec_Custom_VPN_Test_Report.md # Custom VPN 測試報告
```

## 注意事項

- 腳本預設以**非 headless 模式**執行（可觀察瀏覽器操作過程），如需背景執行可在 `config.yaml` 設定 `headless: true`
- 測試完成後腳本會自動復原 DUT 設定（移除 VPN、還原 ge3 LAN IP 為 `default_lan_cidr`）
- PC 的 LAN IP 透過 DHCP 動態取得，腳本會自動偵測實際 IP 用於測試
- `config.yaml` 含敏感資訊（帳密），已加入 `.gitignore`，釋出時請使用 `config.yaml.example`
