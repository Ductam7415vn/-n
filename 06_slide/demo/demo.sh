#!/usr/bin/env bash
# Demo trước hội đồng: quét InsecureBankv2 (và tuỳ chọn NewPipe) rồi mở báo cáo HTML.
#   bash 06_slide/demo/demo.sh            # quét thật, dùng cache nếu đã giải nén (≈ 0,2 s), lần đầu ≈ 19 s
#   bash 06_slide/demo/demo.sh --cold     # xoá cache của lần demo trước để chạy cả JADX (≈ 19 s)
#   bash 06_slide/demo/demo.sh --newpipe  # thêm app thật NewPipe (lần đầu ≈ 45 s)
#   bash 06_slide/demo/demo.sh --offline  # không quét, mở báo cáo đã chạy sẵn trong 06_slide/demo/
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEMO="$ROOT/06_slide/demo"
WORK="${TMPDIR:-/tmp}/apiscan-demo-work"
OUT="${TMPDIR:-/tmp}/apiscan-demo-out"
APISCAN=(python3 "$ROOT/04_code/scripts/apiscan.py")
command -v apiscan >/dev/null && APISCAN=(apiscan)

cold=0 newpipe=0 offline=0
for arg in "$@"; do
  case "$arg" in
    --cold) cold=1 ;;
    --newpipe) newpipe=1 ;;
    --offline) offline=1 ;;
    *) echo "Tham số không hợp lệ: $arg" >&2; exit 2 ;;
  esac
done

if [ "$offline" = 1 ]; then
  open "$DEMO/insecurebankv2/report.html"
  [ "$newpipe" = 1 ] && open "$DEMO/newpipe/report.html"
  exit 0
fi

for tool in apktool jadx; do
  command -v "$tool" >/dev/null || { echo "Thiếu $tool — chạy lại với --offline" >&2; exit 2; }
done
[ "$cold" = 1 ] && rm -rf "$WORK"

scan() {
  local apk="$1" name="$2"
  echo
  echo "\$ apiscan scan $(basename "$apk") --min-confidence medium"
  local start=$SECONDS
  "${APISCAN[@]}" scan "$apk" -o "$OUT/$name" --work-dir "$WORK" --min-confidence medium || {
    echo "Quét lỗi — mở báo cáo chạy sẵn" >&2; open "$DEMO/$name/report.html"; return; }
  echo "Thời gian: $((SECONDS - start)) s"
  open "$OUT/$name/report.html"
}

scan "$ROOT/04_code/target-app/InsecureBankv2.apk" insecurebankv2
[ "$newpipe" = 1 ] && scan "$ROOT/04_code/target-app/org.schabi.newpipe_1015.apk" newpipe
exit 0
