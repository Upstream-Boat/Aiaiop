# 规则库与运行时目录

`data/` 下只随源码带必须分发的小文件（`oui/nmap-mac-prefixes`，约 1MB）。
三套体积较大的规则库不在 git 里（合计约 650MB），首次部署时按下面方式拉取。

| 资源 | 体积 | 获取方式 | 被谁用 |
|---|---|---|---|
| `cve_cache_sm_por.sqlite` | ~270MB | `python3 scripts/update_rules.py --cve` | `cve_match_sm_por`（39.3 万条 CVE） |
| `exploit-db/` | ~295MB | `python3 scripts/update_rules.py --exploit-db` | `exploit_search`、`poc_runner_sm_por` |
| `nuclei-templates/` | ~85MB | `python3 scripts/update_rules.py --nuclei` | `nuclei_scan`（1.3 万+ 模板） |
| `oui/nmap-mac-prefixes` | ~1MB | 已随仓库提供 | `network_inspect` 的 MAC 厂商识别 |
| `nvd_api_key.txt` | — | 可选，写入你自己的 NVD key 可加速 CVE 更新 | `update_rules.py` |

一条命令全拉：

```bash
python3 scripts/update_rules.py --all
python3 scripts/update_rules.py --status   # 只看各库当前版本，不联网
```

**约束**：`update_rules.py` 只允许写入本 skill 的 `data/` 目录，指向目录之外的路径会直接拒绝执行。

**凭据不分发**：`nvd_api_key.txt` 不在版本库里（见仓库根 `.gitignore`）。
没有 NVD key 也能更新，只是 NVD 限速更严；也可以改用环境变量 `NVD_API_KEY`。

运行时产物（任务轨迹、审计链、报告）落在 `data/runtime/`，同样不进版本库。
