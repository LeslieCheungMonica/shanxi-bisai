from modelscope import AutoModelForCausalLM, AutoTokenizer
import torch
import torch_npu  # 添加昇腾NPU支持
import os

# 设置NPU设备
device = torch.device("npu:0")  # 使用第一个NPU设备

model_name = "UCSB-SURFI/VulnLLM-R-7B"

tokenizer = AutoTokenizer.from_pretrained(model_name, use_fast=False)

# 在NPU上加载模型
model = AutoModelForCausalLM.from_pretrained(
    model_name, 
    torch_dtype=torch.bfloat16,
    device_map="npu",  # 改为npu
    # 或者使用: device_map={"": "npu:0"}
)

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

    messages = [{"role": "user", "content": prompt}]
    text = tokenizer.apply_chat_template(
        messages, tokenize=False, add_generation_prompt=True
    )
    
    # 将输入移动到NPU
    model_inputs = tokenizer([text], return_tensors="pt")
    model_inputs = {k: v.to(device) for k, v in model_inputs.items()}

    # 生成时确保模型在NPU上
    with torch.npu.device(device):  # 设置当前NPU设备
        generated_ids = model.generate(
            model_inputs.input_ids, 
            max_new_tokens=1024
        )
    
    generated_ids = [
        output_ids[len(input_ids) :]
        for input_ids, output_ids in zip(model_inputs.input_ids, generated_ids)
    ]

    response = tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]

    safe_name = filename.rsplit(".", 1)[0]
    output_path = os.path.join(output_dir, f"{safe_name}_report.md")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"# 文件：{filename}\n\n{response}")
    print(f"报告已生成：{output_path}")