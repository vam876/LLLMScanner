
# LLM本地部署服务未授权访问扫描工具

## 项目简介

LLM本地部署服务未授权访问扫描工具是一款专为检测大语言模型服务安全漏洞而设计的工具，可以帮助您发现网络中未授权的LLM服务访问点。通过使用该工具，您可以快速识别潜在的安全风险，确保您的LLM服务部署环境的安全性。

本工具支持多种常见LLM服务的漏洞检测，包括但不限于以下几种：
- **Ollama**
- **vLLM**
- **LM Studio**
- **llama.cpp**
- **Mozilla-Llamafile**
- **Jan AI**
- **Cortex API**
- **Local-LLM**
- **LiteLLM API**
- **GPT4All API Server**
- **OpenAI 兼容API接口**

## 技术支持

由 **LocalAPI.ai** 提供技术指导。

**LocalAPI.ai** 是一款为Ollama量身打造的管理工具，同时兼容vLLM、LM Studio、llama.cpp等多种LLM服务，致力于提供高效本地AI交互体验。通过使用LocalAPI.ai，您可以更便捷地管理和部署您的LLM服务。

## 联系我们

如果您在使用过程中遇到任何问题，或者有任何建议和反馈，请随时通过以下方式联系我们：

- **官方Github**：https://github.com/vam876/LLLMScanner/

我们非常期待您的反馈，以便我们不断改进和优化工具。

## 关于LLLM Scanner

### 主要功能

![image-1](https://github.com/user-attachments/assets/53e61bbf-bfde-4be4-9c81-e2a3b772da72)
![image-2](https://github.com/user-attachments/assets/cc421b72-13c4-4377-8d6e-ad3b2b8930b6)

- **端口扫描**：自动发现本地运行的LLM服务，快速定位可能存在的服务端口。
- **漏洞检测**：针对已知的LLM服务漏洞进行检测，涵盖多种常见的安全问题。
- **详细报告**：生成详细的扫描报告，包括发现的漏洞、风险等级、修复建议等，帮助用户全面了解安全状况。

### 支持检测的漏洞列表

以下是当前系统支持检测的LLM服务未授权访问漏洞：

| 服务名称           | 默认端口 | 漏洞名称                     |
|--------------------|----------|------------------------------|
| Ollama             | 自动探测 | Ollama 未授权访问漏洞         |
| vLLM               | 自动探测 | vLLM 未授权访问漏洞           |
| LM Studio          | 自动探测 | LM Studio 未授权访问漏洞      |
| llama.cpp          | 自动探测 | llama.cpp 未授权访问漏洞      |
| Mozilla-Llamafile  | 自动探测 | Mozilla-Llamafile 未授权访问漏洞 |
| Jan AI             | 自动探测 | Jan AI 未授权访问漏洞         |
| Cortex API         | 自动探测 | Cortex API 未授权访问漏洞     |
| Local-LLM          | 自动探测 | Local-LLM 未授权访问漏洞      |
| LiteLLM API        | 自动探测 | LiteLLM API 未授权访问漏洞    |
| GPT4All API Server | 自动探测 | GPT4All API Server 未授权访问漏洞 |
| OpenAI 兼容API接口 | 自动探测 | OpenAI API 未授权访问漏洞     |
