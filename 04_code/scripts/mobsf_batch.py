#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Chạy phân tích TĨNH của MobSF (bản Docker chạy cục bộ) trên nhiều APK và lưu báo cáo JSON — dùng để đối chứng
với apiscan trên cùng tập ứng dụng.

Khởi động MobSF (chỉ lắng nghe trên máy):
    docker run -d --name mobsf -p 127.0.0.1:8000:8000 -e MOBSF_API_KEY=<khoá> \\
        opensecurity/mobile-security-framework-mobsf:latest
Chạy:
    python3 mobsf_batch.py --api-key <khoá> --out 03_benchmark/ket-qua-test/mobsf 04_code/target-app/*.apk

Chỉ gọi REST API của MobSF ở 127.0.0.1 (upload → scan → report_json); không cài, không chạy ứng dụng.
Trường "strings" (mọi chuỗi trích từ APK, ~90% dung lượng báo cáo) bị bỏ khi lưu; báo cáo đầy đủ vẫn còn trong MobSF.

Lưu ý: SKIP_CLASS_PATH mặc định của MobSF chứa 'com/android/' nên bỏ qua toàn bộ mã của InsecureBankv2
(package com.android.insecurebankv2) → phần phân tích mã trả 0 kết quả cho app này. Muốn quét lại sau khi đổi
cấu hình thì dùng --re-scan (MobSF chỉ CẬP NHẬT bản ghi cũ khi re_scan=1, app chưa quét lần nào sẽ không có báo cáo).
"""
import argparse
import json
import os
import subprocess
import sys
import time


def api(base: str, key: str, endpoint: str, *form: str) -> dict:
    cmd = ["curl", "-s", "-S", "--fail-with-body", "--max-time", "3600", "-H", f"Authorization: {key}",
           f"{base}/api/v1/{endpoint}"]
    for f in form:
        cmd += ["-F", f] if f.startswith("file=") else ["--data-urlencode", f]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode:
        raise RuntimeError(f"{endpoint}: {out.stdout[-500:]} {out.stderr[-500:]}")
    return json.loads(out.stdout)


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("apks", nargs="+")
    p.add_argument("--api-key", required=True)
    p.add_argument("--url", default="http://127.0.0.1:8000")
    p.add_argument("--out", required=True)
    p.add_argument("--re-scan", action="store_true")
    a = p.parse_args(argv)
    os.makedirs(a.out, exist_ok=True)
    for apk in a.apks:
        name = os.path.basename(apk)
        dest = os.path.join(a.out, name.replace(".apk", ".json"))
        if os.path.exists(dest):
            print(f"Đã có, bỏ qua: {name}")
            continue
        t0 = time.time()
        up = api(a.url, a.api_key, "upload", f"file=@{apk}")
        api(a.url, a.api_key, "scan", f"hash={up['hash']}", f"re_scan={int(a.re_scan)}")
        report = api(a.url, a.api_key, "report_json", f"hash={up['hash']}")
        report.pop("strings", None)
        report["_apiscan_meta"] = {"apk": name, "md5": up["hash"], "seconds": round(time.time() - t0, 1),
                                   "dropped": ["strings"]}
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False)
        print(f"{name}: {time.time() - t0:.0f} s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
