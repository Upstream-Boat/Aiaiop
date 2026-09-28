#!/usr/bin/env bash
# 安装 sec-assessment 到某个 agent 的 skills 目录。
#
# 自包含：规则库（CVE 库 / Exploit-DB / nuclei 模板 / nmap OUI 表）都在 skill 目录内，
# 复制过去即可用，不需要额外配置路径。
#
# 用法:
#   ./install.sh                          # 装到 ~/.codex/skills/sec-assessment（复制）
#   ./install.sh --link                   # 同上，但用软链接（省 ~935MB 空间）
#   ./install.sh /path/to/skills          # 指定 skills 根目录
#   ./install.sh /path/to/skills --link
#
# 只复制 skill 本体：交付包里的 console/（管理台）与 __pycache__ 不会进 skills 目录。
set -euo pipefail

SRC="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
NAME="$(basename "$SRC")"
LINK=0
DEST_ROOT=""

for arg in "$@"; do
  case "$arg" in
    --link) LINK=1 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) DEST_ROOT="$arg" ;;
  esac
done

if [ -z "$DEST_ROOT" ]; then
  DEST_ROOT="${CODEX_HOME:-$HOME/.codex}/skills"
fi
DEST="$DEST_ROOT/$NAME"

echo "源目录   : $SRC"
echo "目标目录 : $DEST"
echo

command -v python3 >/dev/null || { echo "[错误] 缺少 python3"; exit 1; }

if [ "$LINK" -eq 1 ]; then
  mkdir -p "$DEST_ROOT"
  [ -e "$DEST" ] && { echo "[跳过] $DEST 已存在，未改动"; exit 0; }
  ln -s "$SRC" "$DEST"
  echo "[完成] 已创建软链接"
else
  NEED_KB=$(du -sk "$SRC" | cut -f1)
  AVAIL_KB=$(df -Pk "$DEST_ROOT" 2>/dev/null | awk 'NR==2{print $4}' || df -Pk "$(dirname "$DEST_ROOT")" | awk 'NR==2{print $4}')
  echo "需要空间 : $((NEED_KB / 1024)) MB"
  echo "可用空间 : $((AVAIL_KB / 1024)) MB"
  if [ "$AVAIL_KB" -lt "$((NEED_KB + 102400))" ]; then
    echo "[错误] 空间不足（需留 100MB 余量），或用 --link 安装"
    exit 1
  fi
  mkdir -p "$DEST_ROOT"
  # 只装 skill 本体。交付包里 console/ 可能与 skill 同级或就在 skill 目录内，
  # 那是给人看的管理台，不属于 skill，不跟着进 agent 的 skills 目录。
  if command -v rsync >/dev/null; then
    rsync -a --delete-after \
      --exclude 'console/' --exclude 'console' \
      --exclude '__pycache__/' --exclude '*.pyc' \
      "$SRC/" "$DEST/"
  else
    rm -rf "$DEST"
    mkdir -p "$DEST"
    (cd "$SRC" && tar -cf - --exclude='./console' --exclude='*/__pycache__' \
        --exclude='*.pyc' .) | (cd "$DEST" && tar -xf -)
  fi
  echo "[完成] 已复制到 $DEST"
fi

echo
echo "── 安装后自检 ──"
python3 "$DEST/scripts/check_deps.py" || true
echo
echo "调用示例:"
echo "  cd $DEST/scripts"
echo "  python3 call.py --list"
echo "  python3 call.py network_survey '{\"target\":\"192.168.1.0/24\"}'"
