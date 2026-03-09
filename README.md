# IPSec Site-to-Site VPN Automated Test

Zyxel USG FLEX 500H / 700H 產品的 IPSec Site-to-Site VPN 自動化測試工具。

透過 Playwright 操作 DUT Web UI 完成 VPN 設定，並透過 SSH 在測試 PC 上執行網路驗證工具（ping、iperf3、traceroute、MTU、TCP），最終產生含截圖與完整測試輸出的 Markdown 報告。

## 網路拓撲

```
PC-B (LAN)                              PC-C (LAN)
    |                                       |
 [ge3 LAN]                              [ge3 LAN]
DUT-A (USG FLEX 500H)              DUT-B (USG FLEX 500H)
 [ge1 WAN]                              [ge1 WAN]
    |____________ IPSec Tunnel ______________|
```

## 快速開始

### 方式 A：使用預編譯執行檔（推薦）

無需安裝 Python 或任何套件，下載即可執行。

```bash
# 1. 從 Release 頁面下載並解壓
tar xzf ipsec_vpn_test-macOS-arm64.tar.gz
cd ipsec_vpn_test

# 2. 設定參數檔
cp config.yaml.example config.yaml
# 編輯 config.yaml，填入 DUT / PC 的 IP 位址與帳密

# 3. 執行測試
./ipsec_vpn_test wizard    # Wizard VPN 測試
./ipsec_vpn_test custom    # Custom VPN 測試（5 組設定）
./ipsec_vpn_test all       # 全部執行
```

> 唯一前置需求：`sshpass`
>
> - macOS：`brew install hudochenkov/sshpass/sshpass`
> - Ubuntu：`sudo apt install sshpass`

### 方式 B：從原始碼執行

首次執行會自動建立虛擬環境、安裝 Python 套件與 Chromium 瀏覽器。

```bash
git clone <repo-url> && cd ipsec-vpn-test
cp config.yaml.example config.yaml    # 編輯填入實際設定

./run.sh wizard    # Wizard VPN 測試
./run.sh custom    # Custom VPN 測試
./run.sh all       # 全部執行
```

> 前置需求：Python 3.9+ 和 `sshpass`

### 方式 C：自行編譯

```bash
./build.sh
# 產生 dist/ipsec_vpn_test/ 目錄（含 Python runtime + Chromium，約 470MB）
```

## 測試模式

### Wizard 模式（`wizard`）

透過 VPN Wizard 建立 IKEv2 Policy-Based VPN，執行 10 項連通性測試：

| 類別 | 測試工具 | 說明 |
|------|---------|------|
| ICMP 連通性 | `ping` | 雙向跨隧道 ping（PC-B ↔ PC-C、PC ↔ 對端 DUT LAN gateway） |
| 吞吐量 | `iperf3` | 雙向 TCP 吞吐量（10 秒） |
| 路由驗證 | `traceroute` | 確認流量經過 IPSec 隧道 |
| MTU 測試 | `ping -s 1400 -M do` | 1400B payload + DF bit，驗證無分片問題 |
| TCP 連線 | `netcat (nc)` | 跨隧道 TCP 連線驗證 |

### Custom 模式（`custom`）

手動設定 VPN 參數，依序執行 5 組不同的 IKEv1/IKEv2 + 加密/驗證組合，每組執行 6 項測試：

| # | 名稱 | IKE | P1 加密 | P1 驗證 | P2 加密 | P2 驗證 |
|---|------|-----|---------|---------|---------|---------|
| 1 | Custom_IKEv2_AES256_SHA256 | IKEv2 | AES256-CBC | SHA256 | AES256-CBC | SHA256 |
| 2 | Custom_IKEv2_AES128GCM_SHA512 | IKEv2 | AES128-GCM | SHA512 | AES128-GCM | Built-in |
| 3 | Custom_IKEv1_AES256_SHA256 | IKEv1 | AES256-CBC | SHA256 | AES256-CBC | SHA256 |
| 4 | Custom_IKEv1_3DES_SHA1 | IKEv1 | 3DES-CBC | SHA1 | 3DES-CBC | SHA1 |
| 5 | Custom_IKEv2_AES256GCM_SHA384 | IKEv2 | AES256-GCM | SHA384 | AES256-GCM | Built-in |

> GCM 加密模式的 Phase 2 驗證為 Built-in（由硬體自動處理），DH Group 全部使用預設值（DH2 + DH14）。

## 自動化流程

```
1. 設定 LAN 子網（DUT-A: 192.168.1.1/24, DUT-B: 192.168.2.1/24）
2. 更新 PC DHCP 並偵測實際 LAN IP
3. 設定 IPSec VPN（Wizard 或 Custom 模式）
4. 等待 VPN 隧道建立（15 秒）
5. 執行連通性測試（ping, iperf3, traceroute, MTU, TCP）
6. 產生 Markdown 測試報告（含截圖與完整工具輸出）
7. 移除 VPN、復原 DUT ge3 LAN 設定
```

## 設定檔說明

`config.yaml` 範例：

```yaml
# DUT 登入帳密
dut_user: "admin"
dut_pass: "your_password"

# 測試 PC SSH 帳密
pc_user: "testuser"
pc_pass: "your_password"

# VPN 設定
vpn_name: "S2S_Test"
psk: "YourPreSharedKey"

# DUT-A
dut_a:
  name: "DUT-A"
  mgmt_ip: "192.168.121.x"      # 管理介面 IP
  wan_ip: "192.168.111.x"        # ge1 WAN IP
  lan_subnet: "192.168.1.0/24"   # VPN Policy 的本地子網
  lan_gateway: "192.168.1.1"     # ge3 LAN Gateway

# DUT-B
dut_b:
  name: "DUT-B"
  mgmt_ip: "192.168.121.x"
  wan_ip: "192.168.111.x"
  lan_subnet: "192.168.2.0/24"
  lan_gateway: "192.168.2.1"

# PC-B（DUT-A 後端測試 PC）
pc_b:
  mgmt_ip: "192.168.121.x"      # 管理介面 IP（SSH 連線用）
  lan_ip: "192.168.1.x"          # 預期 LAN IP（DHCP 更新後自動偵測）

# PC-C（DUT-B 後端測試 PC）
pc_c:
  mgmt_ip: "192.168.121.x"
  lan_ip: "192.168.2.x"

# 測試選項
headless: false                   # true = 背景執行瀏覽器
screenshot_dir: "screenshots"
default_lan_cidr: "192.168.168.1/24"  # 測試完畢後復原的 LAN CIDR
```

## 環境需求

### 控制端

| 執行方式 | 需求 |
|---------|------|
| 預編譯執行檔 | `sshpass` |
| 原始碼 (`run.sh`) | Python 3.9+、`sshpass`（其餘自動安裝） |
| 自行編譯 (`build.sh`) | Python 3.9+（自動安裝 PyInstaller 等） |

### 測試 PC（PC-B, PC-C）

- Ubuntu Linux
- 已安裝：`ping`、`traceroute`、`iperf3`、`netcat (nc)`
- 透過 DHCP 從 DUT 取得 LAN IP
- 管理介面（獨立網段）可供 SSH 連線

### DUT（Device Under Test）

- Zyxel USG FLEX 500H / 700H
- Web UI 可透過管理 IP 存取（HTTPS）
- ge1 為 WAN 介面，ge3 為 LAN 介面

## 專案結構

```
ipsec-vpn-test/
├── ipsec_vpn_test.py          # 主程式（wizard / custom / all 模式）
├── run.sh                     # 一鍵執行（自動建立 venv 環境）
├── build.sh                   # PyInstaller 打包腳本
├── config.yaml.example        # 參數檔範本
├── README.md
└── .gitignore
```

### 預編譯發布包結構

```
ipsec_vpn_test/
├── ipsec_vpn_test             # 可執行檔
├── config.yaml.example        # 複製為 config.yaml 並編輯
├── screenshots/               # 測試截圖輸出目錄
└── _internal/                 # Python runtime + Playwright + Chromium
```

## 輸出檔案

| 檔案 | 說明 |
|------|------|
| `IPSec_VPN_Test_Report.md` | Wizard VPN 測試報告 |
| `IPSec_Custom_VPN_Test_Report.md` | Custom VPN 測試報告（5 組設定） |
| `screenshots/*.png` | Web UI 操作截圖與 VPN 狀態頁面 |

## 注意事項

- 腳本預設以**非 headless 模式**執行（可觀察瀏覽器操作過程），如需背景執行可在 `config.yaml` 設定 `headless: true`
- 測試完成後腳本會自動復原 DUT 設定（移除 VPN、還原 ge3 LAN IP 為 `default_lan_cidr`）
- PC 的 LAN IP 透過 DHCP 動態取得，腳本會自動偵測實際 IP 用於測試
- `config.yaml` 含敏感資訊（帳密），已加入 `.gitignore`
