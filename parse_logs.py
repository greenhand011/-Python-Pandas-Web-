import re
import pandas as pd
from datetime import datetime
from sklearn.feature_extraction.text import CountVectorizer
import os

LOG_FILE = 'error.log'

# 正则表达式模式
log_pattern = re.compile(
    r"\[(?P<time>[^\]]+)\]\s+"
    r"\[:error\]\s+"
    r"\[pid\s+(?P<pid>\d+):tid\s+(?P<tid>\d+)\]\s+"
    r"\[client\s+(?P<ip>[\d\.]+):(?P<port>\d+)\]\s+"
    r"script\s+'(?P<script>[^']+)'"
)

def parse_line(line: str):
    m = log_pattern.search(line)
    if not m:
        return None
    d = m.groupdict()
    try:
        time_dt = datetime.strptime(d["time"], "%a %b %d %H:%M:%S.%f %Y")
    except Exception:
        time_dt = None
    return {
        "time_raw": d["time"],
        "time_dt": time_dt,
        "client_ip": d["ip"],
        "client_port": d["port"],
        "script": d["script"]
    }

def main():
    # 检查文件是否存在
    if not os.path.exists(LOG_FILE):
        print(f"错误：文件 {LOG_FILE} 不存在！")
        print(f"当前目录：{os.getcwd()}")
        return
    
    rows = []
    with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            r = parse_line(line)
            if r:
                rows.append(r)
    
    print(f"[+] 成功解析日志行数：{len(rows)}")
    
    if len(rows) == 0:
        print("警告：没有解析到任何数据！")
        return
    
    # 构建DataFrame
    df = pd.DataFrame(rows)
    print(f"[+] DataFrame 形状：{df.shape}")
    
    # 数据清洗
    df = df.dropna()
    df = df.drop_duplicates()
    print(f"[+] 清洗后日志条目数：{len(df)}")
    
    if len(df) == 0:
        print("警告：清洗后没有数据！")
        return
    
    # 查看前20个脚本路径
    print("\n[+] 前20个解析出的脚本路径：")
    for i, script in enumerate(df['script'].head(20)):
        print(f"{i+1}: {script}")
    
    # 提取文件名
    df['file'] = df['script'].apply(lambda x: x.split('/')[-1])
    
    # 统计信息
    print("\n[+] Top 20 客户端 IP：")
    print(df['client_ip'].value_counts().head(20))
    
    print("\n[+] Top 20 被请求文件：")
    print(df['file'].value_counts().head(20))
    
    print("\n[+] Top 20 完整脚本路径：")
    print(df['script'].value_counts().head(20))
    
    # 保存结果
    df.to_csv('error_cleaned.csv', index=False)
    print("\n[+] 清洗后的日志已保存为 error_cleaned.csv")
    
    # 分析不同的向量化方式
    print("\n" + "="*50)
    print("向量化分析")
    print("="*50)
    
    # 方式1：默认向量化（按单词）
    print("\n[方式1] 默认向量化（按单词）：")
    vectorizer1 = CountVectorizer()
    X1 = vectorizer1.fit_transform(df['script'])
    print(f"特征矩阵维度：{X1.shape}")
    print("前10个特征词：", vectorizer1.get_feature_names_out()[:10])
    
    # 方式2：按路径部分向量化
    print("\n[方式2] 按路径部分向量化：")
    vectorizer2 = CountVectorizer(token_pattern=r'[^/]+')  # 按斜杠分割
    X2 = vectorizer2.fit_transform(df['script'])
    print(f"特征矩阵维度：{X2.shape}")
    print("前10个特征词：", vectorizer2.get_feature_names_out()[:10])
    
    # 方式3：只分析文件名
    print("\n[方式3] 文件名向量化：")
    vectorizer3 = CountVectorizer()
    X3 = vectorizer3.fit_transform(df['file'])
    print(f"特征矩阵维度：{X3.shape}")
    print("前10个特征词：", vectorizer3.get_feature_names_out()[:10])
    
    # 方式4：分析文件扩展名
    print("\n[方式4] 文件扩展名分析：")
    # 提取文件扩展名
    def get_extension(filename):
        parts = filename.split('.')
        return parts[-1] if len(parts) > 1 else 'no_extension'
    
    df['extension'] = df['file'].apply(get_extension)
    print("文件扩展名统计：")
    print(df['extension'].value_counts().head(10))
    
    # 分析潜在的攻击特征
    print("\n" + "="*50)
    print("安全分析报告")
    print("="*50)
    
    # 1. 高频IP分析
    ip_counts = df['client_ip'].value_counts()
    print(f"1. 总共有 {len(ip_counts)} 个不同的IP地址")
    print(f"2. 请求最多的IP：{ip_counts.head(5).to_dict()}")
    
    # 2. 敏感文件检测
    sensitive_keywords = ['admin', 'login', 'config', 'backup', 'test', 'wp', 'phpmyadmin', 'sql']
    sensitive_requests = []
    for script in df['script']:
        for keyword in sensitive_keywords:
            if keyword in script.lower():
                sensitive_requests.append(script)
                break
    
    print(f"3. 敏感文件请求次数：{len(sensitive_requests)}")
    
    # 3. 异常请求模式
    # 检查短时间内大量请求
    if 'time_dt' in df.columns and not df['time_dt'].isnull().all():
        df = df.sort_values('time_dt')
        time_diffs = df['time_dt'].diff().dt.total_seconds()
        rapid_requests = df[time_diffs < 1]  # 1秒内的连续请求
        print(f"4. 快速连续请求（<1秒）：{len(rapid_requests)} 次")
    
    print("\n[✓] 分析完成！")

if __name__ == "__main__":
    main()