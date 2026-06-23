import os
import hashlib
import csv
import json
from openai import OpenAI

client = OpenAI(base_url="http://0.0.0.0:8999/v1", api_key="token-sdc123")

files_dir = "files"
output_dir = "output"
csv_path = os.path.join(output_dir, "vuln_statistics.csv")
os.makedirs(output_dir, exist_ok=True)

csv_fields = [
    "项目名",
    "目标文件",
    "目标文件路径",
    "文件md5",
    "是否存在漏洞",
    "漏洞起始行",
    "漏洞结束行",
    "漏洞编号",
    "漏洞类型",
    "漏洞描述",
]

csv_exists = os.path.isfile(csv_path)

VULN_TYPES = [
    "PHP文件包含",
    "数据层查询注入",
    "跨域策略过于宽松",
    "代码注入",
    "敏感信息存储不安全",
    "服务端请求伪造（SSRF）",
    "使用计算成本不足的密码哈希",
    "动态确定的属性未受控修改",
    "LDAP注入",
    "SQL注入",
    "缺少授权",
    "类型混淆",
    "包含来自不可信控制范围的功能",
    "依赖不可信输入进行安全决策",
    "硬编码凭据",
    "跨站脚本（XSS）",
    "越界写入",
    "OS命令注入",
    "资源分配无限制",
    "文件或目录权限设置不正确",
    "文件名或路径的外部控制",
    "异常处理不当",
    "比较不正确",
    "缺少保护机制",
    "无控制的递归",
    "释放后使用",
    "XPath注入",
    "密码恢复机制薄弱",
    "不安全的直接对象引用（IDOR）",
    "动态变量评估",
    "变量提取错误",
    "注释中的敏感信息",
    "Cookie未设置Secure属性",
    "会话过期不足",
    "XML外部实体注入（XXE）",
    "开放重定向",
    "GET请求中的敏感信息",
    "Cookie中依赖不可信输入",
    "外部可访问的文件或目录",
    "日志中信息泄露",
    "Web浏览器缓存敏感信息",
    "凭据保护不足",
    "弱密码策略",
    "嵌入恶意代码",
    "反序列化不可信数据",
    "信任边界违反",
    "遗留调试代码",
    "空指针解引用",
    "反射型注入",
    "上传危险类型文件",
    "资源耗尽（拒绝服务）",
    "会话固定",
    "竞争条件",
    "数据完整性校验不当",
    "跨站请求伪造（CSRF）",
    "密码签名验证不当",
    "数据真实性验证不足",
    "使用弱伪随机数生成器",
    "使用不充分随机值",
    "未使用随机IV",
    "使用弱哈希算法",
    "使用已破解或有风险的加密算法",
    "加密强度不足",
    "硬编码加密密钥",
    "明文传输敏感信息",
    "明文存储敏感信息",
    "未限制认证失败次数",
    "关键功能缺少身份认证",
    "证书验证不当",
    "身份认证不当",
    "访问控制不当",
    "默认权限不正确",
    "硬编码密码",
    "明文存储密码",
    "不当处理多余参数",
    "路径遍历",
    "调试信息泄露",
    "错误信息中的信息泄露",
    "可观察的响应差异",
    "敏感信息泄露",
    "输入验证不当",
    "整数溢出",
    "配置错误",
    "模板注入（SSTI）",
    "正则表达式效率低下（ReDoS）",
    "越界读取",
    "缓冲区溢出",
    "日志注入",
    "HTTP响应拆分",
    "点击劫持",
    "Cookie未设置HttpOnly属性",
    "动态代码执行（eval注入）",
    "XML注入",
    "敏感数据未加密",
]


def extract_json(text):
    text = text.strip()
    if text.startswith("```json"):
        text = text.split("```json", 1)[1]
        if "```" in text:
            text = text.split("```", 1)[0]
    elif text.startswith("```"):
        text = text.split("```", 1)[1]
        if "```" in text:
            text = text.split("```", 1)[0]
    return text.strip()


def try_parse_json(text):
    try:
        return json.loads(text), True
    except json.JSONDecodeError:
        pass

    import re

    match = re.search(r"\[.*\]", text, re.DOTALL)
    if match:
        array_str = match.group(0)
        try:
            return json.loads(array_str), True
        except json.JSONDecodeError:
            pass
        try:
            import demjson3

            result = demjson3.decode(array_str)
            return result, True
        except Exception:
            pass

    try:
        import demjson3

        result = demjson3.decode(text)
        return result, True
    except Exception:
        pass
    return None, False


for project_name in sorted(os.listdir(files_dir)):
    project_path = os.path.join(files_dir, project_name)
    if not os.path.isdir(project_path):
        continue

    project_output_dir = os.path.join(output_dir, project_name)
    os.makedirs(project_output_dir, exist_ok=True)

    for filename in sorted(os.listdir(project_path)):
        filepath = os.path.join(project_path, filename)
        if not os.path.isfile(filepath):
            continue

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            code_snippet = f.read()

        file_md5 = hashlib.md5(code_snippet.encode("utf-8")).hexdigest()

        prompt = f"""你是一个高级漏洞检测模型。
请逐步分析以下代码，判断是否存在安全漏洞。

代码：
{code_snippet}

## 检测约束
1. 漏洞类型必须严格从以下范围内选择，不得输出范围外的漏洞类型：
   PHP文件包含、数据层查询注入、跨域策略过于宽松、代码注入、敏感信息存储不安全、服务端请求伪造（SSRF）、使用计算成本不足的密码哈希、动态确定的属性未受控修改、LDAP注入、SQL注入、缺少授权、类型混淆、包含来自不可信控制范围的功能、依赖不可信输入进行安全决策、硬编码凭据、跨站脚本（XSS）、越界写入、OS命令注入、资源分配无限制、文件或目录权限设置不正确、文件名或路径的外部控制、异常处理不当、比较不正确、缺少保护机制、无控制的递归、释放后使用、XPath注入、密码恢复机制薄弱、不安全的直接对象引用（IDOR）、动态变量评估、变量提取错误、注释中的敏感信息、Cookie未设置Secure属性、会话过期不足、XML外部实体注入（XXE）、开放重定向、GET请求中的敏感信息、Cookie中依赖不可信输入、外部可访问的文件或目录、日志中信息泄露、Web浏览器缓存敏感信息、凭据保护不足、弱密码策略、嵌入恶意代码、反序列化不可信数据、信任边界违反、遗留调试代码、空指针解引用、反射型注入、上传危险类型文件、资源耗尽（拒绝服务）、会话固定、竞争条件、数据完整性校验不当、跨站请求伪造（CSRF）、密码签名验证不当、数据真实性验证不足、使用弱伪随机数生成器、使用不充分随机值、未使用随机IV、使用弱哈希算法、使用已破解或有风险的加密算法、加密强度不足、硬编码加密密钥、明文传输敏感信息、明文存储敏感信息、未限制认证失败次数、关键功能缺少身份认证、证书验证不当、身份认证不当、访问控制不当、默认权限不正确、硬编码密码、明文存储密码、不当处理多余参数、路径遍历、调试信息泄露、错误信息中的信息泄露、可观察的响应差异、敏感信息泄露、输入验证不当、整数溢出、配置错误、模板注入（SSTI）、正则表达式效率低下（ReDoS）、越界读取、缓冲区溢出、日志注入、HTTP响应拆分、点击劫持、Cookie未设置HttpOnly属性、动态代码执行（eval注入）、XML注入、敏感数据未加密。

2. 如果代码中存在上述范围之外的漏洞，请忽略，仅报告范围内的漏洞。
3. 若代码中未发现任何范围内的漏洞，则输出"未检测到漏洞"。

## 输出要求
**只输出以下JSON格式，不要输出任何其他内容（不要输出Markdown代码块标记、不要输出解释说明文字）：**

[
    {
            "id": 1,
        "cwe": "CWE-XXX",
        "cve": "CVE-XXXX-XXXX（如无则填null）",
        "name": "漏洞名称",
        "severity": "严重程度（高危/中危/低危）",
        "type": "漏洞类型（必须从上述范围中选择）",
        "file": "文件名",
        "path": "文件路径",
        "start_line": 0,
        "end_line": 0
        "description": "漏洞描述",
        "code_snippet": "存在问题的代码片段"
    }
]

"""

        resp = client.chat.completions.create(
            model="VulnLLM-R-7B",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt},
            ],
        )
        response = resp.choices[0].message.content

        safe_name = filename.rsplit(".", 1)[0]
        output_path = os.path.join(project_output_dir, f"{safe_name}_report.md")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(f"# 文件：{filename}\n\n{response}")
        print(f"报告已生成：{output_path}")

        # --- parse JSON from response ---
        json_str = extract_json(response)
        data, valid = try_parse_json(json_str)

        if not valid:
            print(f"  [警告] JSON解析失败，尝试修复: {project_name}/{filename}")
            try:
                import demjson3

                data = demjson3.decode(json_str)
                valid = True
            except Exception as e:
                print(f"  [错误] JSON修复失败: {e}")

        relative_path = f"{project_name}/{filename}"

        if not valid or data is None:
            row = {
                "项目名": project_name,
                "目标文件": filename,
                "目标文件路径": relative_path,
                "文件md5": file_md5,
                "是否存在漏洞": "解析失败",
                "漏洞起始行": "",
                "漏洞结束行": "",
                "漏洞编号": "",
                "漏洞类型": "",
                "漏洞描述": "",
            }
            with open(csv_path, "a", newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(f, fieldnames=csv_fields)
                if not csv_exists:
                    writer.writeheader()
                    csv_exists = True
                writer.writerow(row)
            print(f"统计已追加（解析失败）：{relative_path}")
            continue

        if isinstance(data, dict) and len(data) == 0:
            data = []

        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, list):
                    data = v
                    break

        if not isinstance(data, list) or len(data) == 0:
            row = {
                "项目名": project_name,
                "目标文件": filename,
                "目标文件路径": relative_path,
                "文件md5": file_md5,
                "是否存在漏洞": "否",
                "漏洞起始行": "",
                "漏洞结束行": "",
                "漏洞编号": "",
                "漏洞类型": "",
                "漏洞描述": "",
            }
            with open(csv_path, "a", newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(f, fieldnames=csv_fields)
                if not csv_exists:
                    writer.writeheader()
                    csv_exists = True
                writer.writerow(row)
            print(f"统计已追加（无漏洞）：{relative_path}")
            continue

        for vuln in data:
            loc = vuln.get("location", {})
            cwe = vuln.get("cwe", "")
            cve = vuln.get("cve", "")
            vuln_id = cwe
            if cve and cve != "null":
                vuln_id = f"{cwe} / {cve}"

            row = {
                "项目名": project_name,
                "目标文件": filename,
                "目标文件路径": relative_path,
                "文件md5": file_md5,
                "是否存在漏洞": "是",
                "漏洞起始行": loc.get("start_line", ""),
                "漏洞结束行": loc.get("end_line", ""),
                "漏洞编号": vuln_id,
                "漏洞类型": vuln.get("type", ""),
                "漏洞描述": vuln.get("description", ""),
            }
            with open(csv_path, "a", newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(f, fieldnames=csv_fields)
                if not csv_exists:
                    writer.writeheader()
                    csv_exists = True
                writer.writerow(row)

        print(f"统计已追加：{relative_path} ({len(data)} 个漏洞)")
