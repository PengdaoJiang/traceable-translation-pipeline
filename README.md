# Traceable Translation Pipeline

长篇翻译工程中的**原文准备、稳定对齐、修订与审阅记录工具链**。核心代码提取自实际中文文学翻译工作区，处理重复章号、合并题头、原文修订和下游资料失效等真实问题。

## 从原文到可追溯产物

```text
冻结底本 → 精确补丁 → 稳定单元/段落 → 可重建检索
                         ↓
                 生产 → 独立反审 → 裁定记录
```

Python 3.10+，标准库与支持 FTS5 trigram 的 SQLite：

```sh
python -B -m unittest discover -s tests -v
python -B demo.py --out demo-output
```

查看 `demo-output/build/case.json`、`paragraphs.jsonl`、`zh-critical.txt` 和 `corpus.sqlite3`。样例包含重复章号、范围题头和精确错字补丁：显示章号可以重复，稳定 ID 仍然唯一，底本字节保持不变。

## 关键代码

- [corpus.py](translation_core/corpus.py)：从原流水线保留函数及其依赖，包含结构解析、稳定 ID、原文哈希、补丁约束、覆盖核查、原文/修订文并存及 SQLite 检索。
- [governance.py](translation_core/governance.py)：原有审阅记录验证模块，校验任务标识、文件哈希、上下游链接、时序、状态与生产/反审/裁定角色。
- [demo.py](demo.py)：公开适配入口，生成原创测试文本、独立结构清单及明确标记的合成收据，运行上述真实实现。

开发过程使用 Codex 辅助实现和迭代。代码验证资料的完整性和依赖关系，文学质量仍需要实际阅读和判断。

## 工程案例与来源

[为什么章号不能做主键、为什么修订不能改底本、为什么审阅必须锁定上游版本](docs/engineering-cases.md)。

[提取范围与来源](docs/source-provenance.md) 区分保留实现和公开适配。这是原文准备与审阅基础设施，不是全书译文发行版，也不声明原项目所有翻译阶段已经完成。原小说、整书译文和研究资料不随源码公开。

## License

[MIT](LICENSE)，适用于代码、文档及原创测试样例。合成收据中的角色、日期和批准字段仅是测试数据，不表示真实任务执行或文学审定。依赖系统 SQLite/Python 的许可证保持不变。
