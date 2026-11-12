# pefile 版本资源伪装诊断（CompanyName / OriginalFilename）

本目录用**字节级可控的最小 PE32** 验证 pefile（仓库当前版本 `2024.8.26`）
如何呈现多语言、重复键、冲突与损坏的版本资源，并提供一个不丢信息的证据
视图。结论基于当前解析结构本身；资源中的 `CompanyName`、
`OriginalFilename` 只是**攻击者可任意填写的元数据，不是签名身份**。

## 快速复跑

```bash
cd diagnostics
./run_all.sh            # 重建样本 + 生成对照报告
# 或分步：
python3 build_samples.py
python3 diagnose.py            # 文本 + JSON 报告
python3 diagnose.py --json     # 仅机器可读 JSON
python3 diagnose.py samples/s2_duplicate_key.exe   # 单样本
```

产物：

- `samples/s0..s4*.exe`：手工构造的 PE 样本（仅用于解析测试，非可执行程序）。
- `samples/*.manifest.json`：每个块的**绝对文件偏移**、损坏字段位置与语言。
- `reports/diagnostic_report.txt` / `.json`：pefile 视图与无损证据视图对照。

## pefile 当前解析结构的关键行为（源码依据）

| 机制 | 源码位置 | 后果 |
| --- | --- | --- |
| String 条目写入 `entries[key] = value` | `pefile.py:5301` | 同一 StringTable 内重复键被后者覆盖，前者无任何保留 |
| 资源遍历硬编码第一个 name 节点 `entries[0]` | `pefile.py:4918` | 同一 RT_VERSION 类型下额外的 name 节点整体不被解析 |
| String `wLength=0` 时跳到表尾 | `pefile.py:5291-5294` | 当前块及表内后续块被静默丢弃，无警告 |
| 值按 `wValueLength` 限定字数读取 | `pefile.py:5279-5281` | 该字段被改小时只解码前缀，磁盘剩余字节不可见 |
| Translation 每对都重写同一个 dict | `pefile.py:5397-5400` | 多对 Translation 只保留最后一对 |
| 各类解析失败仅 `__warnings.append` 后 break/return | `pefile.py:5155` 等 | 错误分支默认不体现在高层属性里 |
| 不校验 Translation 与 StringTable 语言键一致性 | 整个 `parse_version_information` | 可声明不存在的语言（phantom translation） |

注意：pefile 确实会保留**不同 StringTable** 的全部条目；信息隐藏主要发生在
（a）下游消费者只取第一个表/第一个值，（b）同表重复键折叠，（c）长度损坏
导致的静默截断，（d）多 name 节点遍历限制。

## 样本设计与字节归属

所有偏移以重新生成后的 `*.manifest.json` 与报告为准（下列为当前构建值，
均为**绝对文件偏移**，十六进制）。

### s0_baseline.exe — 干净对照组
单语言 `040904b0`（en-US, charset 0x04B0）。无差异，用于证明工具链对正常
资源的呈现与原始字节一致。

### s1_lang_conflict.exe — 多语言冲突 + Translation 不一致
两个真实 StringTable，语言归属与冲突值：

- `040904b0`（en-US）：`CompanyName='Acme Corp, Redmond WA'`，
  `OriginalFilename='acme_update.exe'`，值字节分别位于报告所示
  `@0x510`、`@0x5a8`。
- `080404b0`（zh-CN）：`CompanyName='Contoso 伪装有限公司'`，
  `OriginalFilename='svchost_helper.exe'`，位于 `@0x630`、`@0x6b0`。
- Var `Translation`（payload `@0x748`）声明两对：
  `0x0409/0x04b0` 与 `0x0411/0x04b0`（ja-JP），但**没有日语 StringTable**。

保留/覆盖/丢弃：

- 两个表的值 pefile 都保留，但 `var.entry` 因 dict 重写只剩最后一对
  `0x0411 0x04b0`，en-US 这对在 pefile 视图里消失。
- 证据视图恢复全部两对 Translation，并把 `041104b0` 标记为
  `phantom_translation`。
- 只取“第一个 StringTable”的报告结论会得到最像正常软件的 Acme 身份，
  完全看不到中文伪装值。

### s2_duplicate_key.exe — 单表重复键（覆盖）
单个 `040904b0` 表内，`CompanyName` 与 `OriginalFilename` 各出现两次：

- `CompanyName` 块头 `@0x4f0`（值 `@0x510`，benign 副本）与
  `@0x554`（值 `@0x574`，`EVIL OPERATOR SECOND COPY`）。
- `OriginalFilename` 块头 `@0x5a8` 与 `@0x5f0`。

pefile 的 `entries` 字典只暴露最后一个值；第一个物理副本仍在磁盘上，
但 pefile 任何高层属性（含 `dump_dict()`）都无法访问。证据视图逐条列出
两个副本及偏移，标记 `duplicate_key_overwritten`，**零警告**。

### s3_corrupt_length.exe — 长度损坏（丢弃 + 截断）
两个独立 name 节点（各自一张表），避免一个表的中断掩盖另一个效应。

- name 1 / `040904b0`：`InternalName` 块（头 `@0x5f8`）的 `wLength` 被置 0。
  pefile 在跳表前已先解码并保留 `InternalName` 自身的值，但随后把入口游标
  直接置为表尾（`pefile.py:5291-5294`），因此其后的 `LegalCopyright`、
  `ProductName` 两个块完全不出现；这些字符串的 UTF-16 字节仍在磁盘上
  （`0x674`、`0x6b4` 起），报告标记 `wlength_zero_drops_tail`，无警告。
- name 2 / `080404b0`：`FileDescription` 块（`wValueLength` 字段
  `@0x7f2`）被改为 4 words，而实际存 31 个字符。pefile 只解码
  `'1234'`；完整值 `'1234567890-truncated-on-purpose'` 由证据视图的
  NUL 终止扫描恢复，标记 `wvaluelength_truncated`。
- 同时该样本含两个 RT_VERSION name 节点，pefile 仅解析 name 1，
  name 2 blob（`@0x718`）在 pefile 视图中整体缺席。

### s4_hidden_name_node.exe — 资源树 name 节点隐藏
RT_VERSION 下两个 name 节点：

- name 1 / `040904b0`：`CompanyName='FIRST NODE VISIBLE'`，pefile 可见。
- name 2 / `080404b0`：blob 起始 `@0x5ac`，含
  `CompanyName='SECOND NODE HIDDEN BY PARSER'` 与
  `OriginalFilename='hidden_second.exe'`。

因 `pefile.py:4918` 只取 `entries[0]`，第二个 blob 根本不进入
`parse_version_information`。证据视图自行三层遍历资源目录
（Type→Name→Language），恢复全部 blob，标记
`rt_version_name_node_skipped`。

## 证据视图如何兼容并补全 pefile

`raw_version_parser.RawVersionParser` 不使用字典折叠，输出每个 String 块的：

- 块头、szKey、value 的绝对文件偏移；
- 声明的 `wLength` / `wValueLength` 与块内实际可用字数；
- 两种值：`value_per_declared_length`（pefile 会得到的结果）与
  `value_full_nul_terminated`（忽略损坏长度后可恢复的完整值）；
- 状态码：`ok` / `wvaluelength_undersized` /
  `wlength_zero_block_and_tail_dropped` / `wvaluelength_overruns_block` 等；
- 所有 Translation 对（修复 pefile 只留最后一对的问题）与全部 name 节点。

`diagnose.py` 的 `discrepancies` 把每个值归类为
`retained / overwritten / dropped / truncated / phantom_translation /
hidden_blob`，使所有可恢复值和错误分支同时可见，避免只报告最像正常软件
的那一条。

## 调查使用约束

- 资源字符串可被任意伪造，**不得**据此认定发行商或文件名；签名身份应以
  Authenticode 签名链、证书校验与时间戳服务为准。
- 本工具只回答“磁盘上到底写了什么、pefile 为什么没显示”，不做信誉判定。
- 样本为手工最小 PE，节区含大量零填充，pefile 会给出零占比提示；诊断器
  已在对照视图中过滤该良性警告，其余解析警告原样保留。
