import os
from openai import OpenAI

client = OpenAI(base_url="http://0.0.0.0.0.0:899/v1", api_key="token-sdc123")

files_dir = "files"
output_dir = "output"
os.makedirs(output_dir, exist_ok=True)

for filename in sorted(os.listdir(files_dir)):
    filepath = os.path.join(files_dir, filename)
    if not os.path.isfile(filepath):
        continue

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        code_snippet = f.read()

    prompt = f"""你是一个高级漏洞检测模型。
请逐步分析以下代码，判断是否存在安全漏洞。

代码：
{code_snippet}

请按照以下格式输出分析结果：

## 漏洞概览
| 漏洞编号 | 漏洞名称 | 严重程度 | 漏洞类型 |
|----------|----------|----------|----------|
|          |          |          |          |

## 漏洞详情

### 漏洞1
- **漏洞描述**：
- **漏洞位置**：
- **漏洞详情**：
- **关键代码片段**：
- **复现方法**：
- **修复建议**：

（如有多个漏洞，请继续列出漏洞2、漏洞3...）

## 总结
| 序号 | 漏洞位置 | 漏洞类型 | 严重程度 | 建议修复优先级 |
|------|----------|----------|----------|----------------|
|      |          |          |          |                |

**核心问题**：
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
    output_path = os.path.join(output_dir, f"{safe_name}_report.md")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"# 文件：{filename}\n\n{response}")
    print(f"报告已生成：{output_path}")
