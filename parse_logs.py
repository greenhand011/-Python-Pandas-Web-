import re
import pandas as pd
from datetime import datetime


# ======================
# 1) 解析单行 error.log
# ======================
log_pattern = re.compile(
    r"\[(?P<time>[^\]]+)\]\s+\[:error\]\s+\[pid\s+(?P<pid>\d+):tid\s+(?P<tid>\d+)\]\s+\[client\s+(?P<ip>[\d\.]+):(?P<port>\d+)\]\s+script '(?P<script>[^']+)' not found"
)


def parse_line(line):
    m = log_pattern.search(line)
    if not m:
        return None

    d = m.groupdict()

    # 转换时间格式：Mon Sep 29 14:38:42.192842 2025
    try:
        d["time_dt"] = datetime.strptime(d["time"], "%a %b %d %H:%M:%S.%f %Y")
    except:
        d["time_dt"] = None

    return {
        "time_raw": d["time"],
        "time_dt": d["time_dt"],
        "client_ip": d["ip"],
        "client_port": d["port"],
        "script": d["script"]
    }


# ======================
# 2) 扫描行为检测逻辑
# ======================
def detect_scanners(df, window_seconds=10, distinct_threshold=10, min_requests=20):
    summary = []

    # 丢弃无法解析的行
    df2 = df.dropna(subset=["client_ip", "time_dt", "script"]).copy()
    df2 = df2.sort_values(["client_ip", "time_dt"])

    for ip, grp in df2.groupby("client_ip"):
        times = list(grp["time_dt"])
        scripts = list(grp["script"])

        total_reqs = len(grp)  # 该 IP 总请求数
        distinct_all = len(set(scripts))  # 该 IP 探测过的不同文件数量

        is_scanner = False
        max_distinct = 0

        # 滑动窗口检测
        left = 0
        for right in range(len(times)):

            while left <= right and (times[right] - times[left]).total_seconds() > window_seconds:
                left += 1

            window_scripts = scripts[left:right + 1]
            distinct_in_window = len(set(window_scripts))

            if distinct_in_window > max_distinct:
                max_distinct = distinct_in_window

            if distinct_in_window >= distinct_threshold:
                is_scanner = True
                break

        # 二级规则：弱扫描器
        if not is_scanner and total_reqs >= min_requests and distinct_all >= distinct_threshold // 2:
            is_scanner = True

        summary.append({
            "client_ip": ip,
            "total_requests": total_reqs,
            "distinct_missing_files": distinct_all,
            f"max_distinct_in_{window_seconds}s": max_distinct,
            "is_scanner": is_scanner
        })

    return pd.DataFrame(summary)


# ======================
# 3) 主流程
# ======================
def main():
    log_file = "error.log"

    print(f"开始读取 {log_file} ...")

    parsed_rows = []
    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            row = parse_line(line)
            if row:
                parsed_rows.append(row)

    print(f"读取到行数： {len(parsed_rows)}")

    df = pd.DataFrame(parsed_rows)
    print(f"解析后条目： {len(df)}")

    # 写出解析好的 CSV
    df.to_csv("error_parsed.csv", index=False)
    print("解析结果已保存： error_parsed.csv")

    # 统计最常被探测的文件
    df["script_basename"] = df["script"].apply(lambda x: x.split("/")[-1] if isinstance(x, str) else x)

    print("\nTop 被探测文件：")
    print(df["script_basename"].value_counts().head(20))

    # 扫描检测
    summary_df = detect_scanners(df)

    # 保存扫描结果
    summary_df.to_csv("scan_summary.csv", index=False)
    print("\n扫描检测结果已保存： scan_summary.csv")

    print("\nsummary_df 字段：", list(summary_df.columns))

    # 打印Top可疑 IP
    print("\nTop 可疑扫描器 IP：")
    print(
        summary_df.sort_values(
            ["is_scanner", "distinct_missing_files", "total_requests"],
            ascending=[False, False, False]
        ).head(10).to_string(index=False)
    )


if __name__ == "__main__":
    main()
