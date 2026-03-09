# IPSec Site-to-Site VPN Automated Test

Zyxel USG FLEX 500H / 700H 產品的 IPSec Site-to-Site VPN 自動化測試工具。透過 Playwright 操作 DUT Web UI 完成 VPN 設定，並透過 SSH 在測試 PC 上執行網路驗證工具，最終產生含截圖與完整測試輸出的 Markdown 報告。

## 網路拓撲

```
PC-B (LAN)                              PC-C (LAN)
    |                                       |
 [ge3 LAN]                              [ge3 LAN]
DUT-A (USG FLEX 500H)              DUT-B (USG FLEX 500H)
 [ge1 WAN]                              [ge1 WAN]
    |____________ IPSec Tunnel ______________|
```

## 測試模式

| 模式 | 說明 |
|------|------|
| `wizard` | 透過 VPN Wizard 建立 IKEv2 Policy-Based VPN，執行完整連通性測試 |
| `custom` | 手動設定 5 組不同 IKEv1/IKEv2 + 加密/驗證組合，逐一測試 |
| `all` | 依序執行 wizard 與 custom 測試 |

### 測試項目

| 類別 | 測試工具 | 說明 |
|------|---------|------|
| ICMP 連通性 | `ping` | 雙向跨隧道 ping（PC-B ↔ PC-C、PC ↔ 對端 DUT LAN gateway） |
| 吞吐量 | `iperf3` | TCP 吞吐量（10 秒） |
| 路由驗證 | `traceroute` | 確認流量經過 IPSec 隧道 |
| MTU 測試 | `ping -s 1400 -M do` | 1400B payload + DF bit，驗證無分片問題 |
| TCP 連線 | `netcat (nc)` | 跨隧道 TCP 連線驗證（僅 wizard 模式） |

### Custom VPN 測試案例

| # | 名稱 | IKE | 加密 | 驗證 | DH |
|---|------|-----|------|------|----|
| 1 | IKEv2_AES256_SHA256 | IKEv2 | AES256-CBC | SHA256 | Default |
| 2 | IKEv2_AES128GCM_SHA512 | IKEv2 | AES128-GCM | SHA512 | Default |
| 3 | IKEv1_AES256_SHA256 | IKEv1 | AES256-CBC | SHA256 | Default |
| 4 | IKEv1_3DES_SHA1 | IKEv1 | 3DES | SHA1 | Default |
| 5 | IKEv2_AES256GCM_SHA384 | IKEv2 | AES256-GCM | SHA384 | Default |

## 快速開始

### 1. 設定參數檔

```bash
cp config.yaml.example config.yaml
```

編輯 `config.yaml`，填入實際的 IP 位址與帳密：

```yaml
dut_user: "admin"
dut_pass: "your_dut_password"
pc_user: "testuser"
pc_pass: "your_pc_password"
vpn_name: "S2S_Test"
psk: "YourPreSharedKey"

dut_a:
  name: "DUT-A"
  mgmt_ip: "192.168.121.x"
  wan_ip: "192.168.111.x"
  lan_subnet: "192.168.1.0/24"
  lan_gateway: "192.168.1.1"

dut_b:
  name: "DUT-B"
  mgmt_ip: "192.168.121.x"
  wan_ip: "192.168.111.x"
  lan_subnet: "192.168.2.0/24"
  lan_gateway: "192.168.2.1"

pc_b:
  mgmt_ip: "192.168.121.x"
  lan_ip: "192.168.1.x"

pc_c:
  mgmt_ip: "192.168.121.x"
  lan_ip: "192.168.2.x"

headless: false
screenshot_dir: "screenshots"
default_lan_cidr: "192.168.168.1/24"
```

### 2. 執行測試

```bash
# 首次執行會自動建立虛擬環境、安裝 Python 套件與 Chromium 瀏覽器
./run.sh wizard    # Wizard VPN 測試
./run.sh custom    # Custom VPN 測試（5 組設定）
./run.sh all       # 全部執行
```

> **唯一前置需求**：Python 3.9+ 和 `sshpass`
>
> macOS 安裝 sshpass：`brew install hudochenkov/sshpass/sshpass`
>
> Ubuntu 安裝 sshpass：`sudo apt install sshpass`

### 自動化流程

```
1. 設定 LAN 子網（ge3 介面）
2. 設定 IPSec VPN（Wizard 或 Custom）
3. 等待 VPN 隧道建立
4. 執行連通性測試（ping, iperf3, traceroute, MTU, TCP）
5. 產生 Markdown 測試報告（含截圖與完整工具輸出）
6. 移除 VPN、復原 DUT 設定
```

## 環境需求

### 控制端（執行腳本的機器）

- Python 3.9+（其餘由 `run.sh` 自動安裝）
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

## 專案結構

```
ipsec-vpn-test/
├── run.sh                     # 一鍵執行腳本（自動建立環境）
├── ipsec_vpn_test.py          # 主程式（含 wizard / custom / all 模式）
├── config.yaml.example        # 參數檔範本
├── README.md
└── .gitignore
```

## 輸出檔案

| 檔案 | 說明 |
|------|------|
| `IPSec_VPN_Test_Report.md` | Wizard VPN 測試報告 |
| `IPSec_Custom_VPN_Test_Report.md` | Custom VPN 測試報告（5 組設定） |
| `screenshots/*.png` | 所有 Web UI 操作截圖與狀態頁面 |

## 注意事項

- 腳本預設以**非 headless 模式**執行（可觀察瀏覽器操作過程），如需背景執行可在 `config.yaml` 設定 `headless: true`
- 測試完成後腳本會自動復原 DUT 設定（移除 VPN、還原 ge3 LAN IP 為 `default_lan_cidr`）
- PC 的 LAN IP 透過 DHCP 動態取得，腳本會自動偵測實際 IP 用於測試
- `config.yaml` 含敏感資訊（帳密），已加入 `.gitignore`，釋出時請使用 `config.yaml.example`
