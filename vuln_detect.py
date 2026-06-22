from modelscope import AutoModelForCausalLM, AutoTokenizer
import torch

model_name = "UCSB-SURFI/VulnLLM-R-7B"

tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(
    model_name, torch_dtype=torch.bfloat16, device_map="auto"
)

# Example Code Snippet
code_snippet = """
void vulnerable_function(char *input) {
    char buffer[50];
    strcpy(buffer, input); // Potential buffer overflow
}
"""

# Prompt Template (Triggering Reasoning)
prompt = f"""You are an advanced vulnerability detection model. 
Please analyze the following code step-by-step to determine if it contains a vulnerability.

Code:
{code_snippet}

Please provide your reasoning followed by the final answer.
"""

messages = [{"role": "user", "content": prompt}]
text = tokenizer.apply_chat_template(
    messages, tokenize=False, add_generation_prompt=True
)
model_inputs = tokenizer([text], return_tensors="pt").to(model.device)

generated_ids = model.generate(model_inputs.input_ids, max_new_tokens=512)
generated_ids = [
    output_ids[len(input_ids) :]
    for input_ids, output_ids in zip(model_inputs.input_ids, generated_ids)
]

response = tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
print(response)
