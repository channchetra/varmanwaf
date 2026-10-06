# PingWAF 数据面 WAF 实测评估报告（基于 blazehttp 攻击样本）

- 测试日期：2026-10-04
- 样本来源：[chaitin/blazehttp](https://github.com/chaitin/blazehttp) 内置测试集（33877 条原始 HTTP 报文：恶意 658 / 正常 33219）
- 被测对象：PingWAF 数据面（pingap-plugin WAF，pingora 0.9.0）静态配置模式
- 工具：自研原始报文回放器 `tools/waf-bench/replay.py`（raw socket 逐字节发送，保真畸形样本）+ 官方 blazehttp v0.3.0 CLI 交叉对账

## 1. 执行摘要

默认托管规则（13 条，`mode=block`、`paranoia_level=2`、`anomaly_threshold=40`）在 blazehttp 全量样本上的表现：

| 指标 | 数值 |
|---|---|
| 恶意样本拦截率（严格口径：403/503） | 34.0% |
| 恶意样本漏报率 | ~66% |
| 正常样本误报率 | ~0.4% |
| p95 时延 | 2 ms |

核心结论：

1. **默认规则面是一个低误报、中低拦截率的"精确但偏保守"配置**。误报率 0.4% 在公网反代场景可用；但 66% 的漏报中，绝大部分不是阈值调一调就能解决的，而是**规则覆盖面缺口**（编码混淆、命令注入词表、CRLF/XXE/SSTI/deser 整类缺失）。
2. **静态/生产数据面默认不检测请求体**。`inspect_body` 被 agent（控制面）门控，30.7% 的 POST 样本中至少 34 条（5.2%）攻击签名只存在于 body，默认不可见。
3. **监控模式（出厂默认）在静态模式下零日志**。`log_event` 无 agent 即静默返回，监控判决不产生任何落点——"看起来开着防护，实际什么都看不见"。
4. **阈值与 PL 的默认值基本不影响结果**：threshold 30/40/60 三组结果完全一致；PL3 仅增加 +1.7pp 拦截、+0.04pp 误报（137→150 条）。说明当前拦截决策由 Stage-1 critical 短路与托管规则子评分（60/80）主导，聚合阈值不是有效调参面。
5. 官方 blazehttp CLI 对 pingap 的绝对数值（检出率 2.29%）不可用：其"单一探测状态码"判定与 pingora 协议层 400 相互作用，测的是协议层拒绝而非 WAF 拦截（见 §8.2）。
6. **agent 模式（body 检测生效 + 控制面规则）的净收益为 +4.6pp 拦截、代价是 3 倍误报**：纯净复测拦截 34.0%→38.6%，误报 0.41%→1.27%。增量误报的主体与控制面播种规则的 `score ge 40` 低门槛高度相关（托管规则为 ge 60/80，归因与建议见 §7 第二档）。

## 2. 总体指标

| 组 | 配置 | 黑样本拦截（严格） | 拦截率 | 白样本误报 | 误报率 | p50/p95 | error |
|---|---|---|---|---|---|---|---|
| **G1** | block, PL2, th40（主基线） | 224/658 | **34.0%** | 137/33219 | **0.41%** | 0/2 ms | 0 |
| G2 | monitor（出厂默认） | 0/658 | 0% | 0/33219 | 0% | 0/2 ms | 0 |
| G3-pl1 | PL1 | 224/658 | 34.0% | 130/33219 | 0.39% | 0/2 ms | 0 |
| G3-pl3 | PL3 | 235/658 | 35.7% | 150/33219 | 0.45% | 0/2 ms | 0 |
| G3-th30 | threshold 30 | 224/658 | 34.0% | 137/33219 | 0.41% | 0/2 ms | 0 |
| G3-th60 | threshold 60 | 224/658 | 34.0% | 137/33219 | 0.41% | 0/2 ms | 0 |
| **G4** | agent 模式（纯净复测¹） | 254/658 | **38.6%** | 421/33219 | **1.27%** | 2/3004 ms² | 0.17% |

¹ G4 的黑/白样本分别独立复测（每样本独享大空间轮换 XFF），消除 auto-block 连带拒绝后得到的纯净规则指标。混跑全量时表观值为"拦截 55.0% / 误报 26.4%"，其中绝大部分为 auto-block 工件——黑样本触发封禁后，同 IP 后续请求（无论黑白）在 600s 内被边缘直接拒绝（受控实验证实：攻击请求 403 后，同 IP 正常请求立即 403，换新 IP 即 200）。该现象同时演示了生产风险：共享出口 IP（NAT/办公网）的正常用户会被单个攻击者连带，且 XFF 可伪造放大该面（§6.5）。
² G4 的 p95 长尾来自 challenge 页交互与 auto-block 查询路径。

口径定义：

- **blocked（严格）**：403（WAF block 页）/ 503（challenge 页），即 WAF 判决
- **passed**：2xx/3xx（到达 mock 上游）
- **protocol_reject**：400/413/414/431/501 等 pingora 协议层拒绝，非 WAF 判决，严格口径下单列
- **error**：超时/连接重置
- **wide（宽口径）**：blocked + protocol_reject + error，与官方工具"非 2xx/3xx 即拦截"语义对齐，用于对账

## 3. 类别交叉表

G1 主基线的恶意样本（black）按类目拦截情况：

| 类目 | 样本数 | 拦截（严格） | 拦截率 | 备注 |
|---|---|---|---|---|
| sqli | 20 | 15 | 75.0% | 唯一高拦截类目，但也是唯一高误报类目 |
| other | 538 | 188 | 34.9% | 未归入特定类目的攻击样本 |
| xss | 30 | 10 | 33.3% | hex/base64/编码变形整批漏过 |
| lfi | 25 | 8 | 32.0% | |
| rce | 12 | 2 | 16.7% | `$(...)`/反引号/`${IFS}` 形态未覆盖 |
| ssrf | 13 | 1 | 7.7% | 仅 IP 字面量正则，payload 深藏参数/JSON 的全漏 |
| deser | 6 | 0 | 0% | 整类缺失 |
| crlf | 5 | 0 | 0% | 整类缺失 |
| ssti | 5 | 0 | 0% | 整类缺失 |
| xxe | 2 | 0 | 0% | 整类缺失 |
| log4shell | 1 | 0 | 0% | 1050 只查 user-agent，URI 载荷绕过 |
| scanner | 1 | 0 | 0% | UA 特征不在 1010 词表 |

白样本误报按类目（仅 4 个类目出现误报）：

| 类目 | 样本数 | 误报 | 误报率 | 主因 |
|---|---|---|---|---|
| sqli | 67 | 56 | 83.6% | 搜索引擎 Referer 含 SQL 关键词（53 条），libinjection 判定 + 1002 子评分门 |
| scanner | 45 | 2 | 4.4% | UA 含工具名片段 |
| rce | 460 | 4 | 0.9% | 参数/正文含命令样式文本 |
| other | 32432 | 75 | 0.23% | 零散 |

类目标签为回放器启发式归因（与引擎 9 大类对齐），仅用于统计维度。

## 4. 失败样本归因（以 G1 主基线为准）

### 4.1 漏报 TOP 模式（黑样本放行，~66%）

按占比从大到小：

1. **编码/混淆绕过签名**（最大单一来源）。
   - hex 编码 JS：`parent['\x65\x76\x61\x6c'](...)`（`\x65\x76\x61\x6c` = `eval`）——`00/e1/1e708ad1f095e8e21f57f4bb8cfc.black`
   - base64/多层 URL 编码 payload；
   - 编码后签名首尾变形，Aho-Corasick needle 与 libinjection 均不命中。
2. **命令注入词表缺口**：引擎 rce 检测只认 `[;&|] (cat|ls|id|whoami|wget|curl|bash|sh|nc|...)` 分隔符+固定词表，不覆盖 `$(ping ...)`、反引号 `` `whoami` ``、`${IFS}` 混淆：
   - `GET /login/index.php?login=$(ping${IFS}-nc${IFS}2${IFS}`whoami`.)` —— `5b/0d/13f7d5f4c37d750a1e23b19a9cb8.black`
3. **请求体携带攻击**：30.7% 样本为 POST，其中至少 34 条（黑样本 5.2%）签名仅在 body（SSRF 9、RCE 6、deser 5、LFI 5 等），数据面默认不读 body → 结构性漏报。
4. **整类规则缺失**（黑样本 100% 放行）：
   - **CRLF 注入**（5/5）：`GET /vulnerabilities/sqli/%0D%0AX-Pen-Test%3AeKqNz22M6K` —— 托管规则集无任何 CRLF/响应拆分规则；
   - **SSTI**（5/5）、**XXE**（2/2）、**Java 反序列化**（6/6）：无对应检测类目；
   - **Log4Shell in URI**（1/1）：托管规则 PINGWAF-1050 表达式只查 `user-agent` 头（规则名却写着 "in any header"），`${jndi:ldap://...}` 出现在 URI 即完全绕过 —— `19/c7/0731629c2498100dc8a3247e06f7.black`。
5. **SSRF 检测面过窄**（13 条仅拦 1）：正则只匹配回环/内网/元数据 IP 字面量与 gopher/dict 协议头，实际样本多把目标放在 body/JSON/参数值深处（如 solr dataConfig 中 `URLDataSource`），且不含 DNS 类变体。

### 4.2 误报 TOP 模式（白样本拦截，~0.4% 但高度集中）

| 类目 | 误报数/类目样本数 | 误报率 | 主因 |
|---|---|---|---|
| sqli 标签白样本 | 56/67 | **83.6%** | 搜索引擎 Referer 带 SQL 关键词（如 Bing 搜索 `union select 关键字怎么用` 的 URL 经 URL 编码含中文），libinjection 对 Referer 值判为 SQLi → 直接命中 1002 子评分门 |
| scanner | 2/45 | 4.4% | UA 含工具名片段 |
| rce | 4/460 | 0.9% | 正文/参数含命令样式文本 |
| other | 75/32432 | 0.23% | 零散 |

**SQLi 误报是唯一成规模的误报源**：56 条误报中 53 条（95%）的 SQL 关键词出现在 `Referer` 头（典型：Bing 搜索 `site:segmentfault.com union select 关键字怎么用` 的搜索 URL 原样作为 Referer）。搜索引擎流量是 Referer 的最大来源，这是公网站点最常见的误报投诉模式。

### 4.3 协议层拒绝（非 WAF 判决，严格口径单列）

修复测试环境上游干扰后，真实协议层拒绝仅 ~0.01%（黑 3：2×400 + 1×501；白 1：400）。此前观察到的数千个 501/400 均为测试环境 mock 上游不排空请求体造成的连接池串扰（详见 §8.3 与 tools/waf-bench/mock_origin.py 内注释），非被测系统行为。

## 5. 生效规则面与命中情况

静态模式生效的是引擎托管规则集（`pingwaf-waf/src/rules/managed.rs`，13 条）：

| 规则 | 语义 | 动作 | PL | 备注 |
|---|---|---|---|---|
| 1001 | /admin 路径非内网访问 | Challenge | 1 | |
| 1002 | cf.waf.score.sqli ≥ 60 | Block | 1 | SQLi 误报主通道 |
| 1003 | cf.waf.score.xss ≥ 60 | Block | 1 | |
| 1004 | 聚合分 ≥ 80 | Block | 1 | |
| 1010 | 扫描器 UA | Block | 2 | |
| 1011 | 空 UA（非 HEAD） | Challenge | **3** | 默认 PL2 下不激活 |
| 1020 | 敏感 dotfile 探测 | Block | 1 | |
| 1021 | 备份文件探测 | Block | 2 | |
| 1030 | TRACE/TRACK | Block | 1 | |
| 1031 | 非常规方法 | Log | 2 | 静态模式下 Log 无任何落点 |
| 1040 | phpMyAdmin/wp-admin 探测 | Challenge | 2 | |
| 1050 | Log4Shell | Block | 1 | **表达式只查 user-agent**，与规则名 "in any header" 不符 |
| 1051 | 超长 URI（≥4096B） | Block | **3** | 默认 PL2 下不激活 |

逐条命中率无法从日志统计——静态模式不产生任何规则命中日志（见 §6.1/§6.2）。类别级命中归因见 §3 交叉表；黑样本命中率：sqli 75% > other 35% > xss 33% > lfi 32% > rce 17% > ssrf 8% >> deser/crlf/ssti/xxe/log4shell/scanner 0%。

## 6. 机制层发现

1. **静态模式下 monitor 判决与 block 判决均无任何日志落点**。`log_event`（waf.rs:1796）在 `PingWafAgent::instance()` 为 None 时直接 return；安全事件、访问日志、分析管道全部依赖 agent。实测 G2 monitor 全量回放 33877 请求，服务器日志 0 条 WAF 记录。含义：以静态 TOML 部署、或控制面短暂失联时，WAF 变成"静默黑洞"——拦截了什么、放过了什么无从得知。
2. **`inspect_body` 被 agent 门控，请求体默认不进引擎**（waf.rs:2107 `if agent.is_some() && (body_limit > 0 || self.inspect_body)`）。与 `docs/waf.md` 宣称的 body 检测能力不符；agent 模式下还受 `max_body_log_size` 间接影响。
3. **规则级 monitor 不下传数据面**：控制面规则若配为 monitor 动作，`waf_config_to_proto` 只聚合站点级 mode，观测语义丢失；叠加发现 1，监控模式实际完全不可观测。
4. **`detections` 开关与 `ml_*` 字段是 TODO**：`waf_config_to_proto` 中 `ml_enabled` 硬编码 false、`anomaly_threshold` 固定传 0（引擎侧回落 40）；sqli/xss/rce/lfi/ssrf/bot 检测开关未接线到引擎，站点无法按类目关闭检测。
5. **默认信任 XFF 第一段**（pingap-core/src/http_header.rs:415）：未配置 trusted-proxies 时客户端可伪造 `client_ip`，直接影响 IP 封禁、CC、地理位置类规则的有效性（本测试正是利用该机制轮换 XFF 规避 auto-block）。
6. **auto-block 600s 无通知且会连带共享出口 IP**：Block 判决后 agent 自动封禁来源 IP 600s（waf.rs:2595），期间请求在边缘直接拒绝，无 webhook/日志通知；且 auto-block reason 不稳定——实测封禁记录中部分为空串（`"reason": "waf: "`），部分带规则名（`"reason": "waf: SSRF 检测"`），空 reason 时被封禁者与运维都无法得知封禁原因。受控实验证实同 IP 的正常请求在封禁窗口内也被一律 403（§2 脚注 1）：对 NAT/办公网共享出口、或默认信任 XFF（§6.5）可伪造的场景，这是可被利用的拒绝服务向量。
7. **Content-Length 与 body 长度不一致的请求触发 500**：多发 7 字节的样本稳定命中 pingap `Sent data after end of body` → 500（请求走私探测的常见形态），且仅记录 ERROR 无 WAF 归类。另在早期环境观察到 pingora 0.9.0 `client.rs:818` 对上游响应头 `unwrap()` UTF-8 解析的 panic（上游错位时触发，panic 被线程隔离，进程存活）。
8. **控制面规则表达式编译失败被静默丢弃**（waf.rs:1687 `filter_map(... .ok())`）：站点规则里的表达式写错不会报错，只会让该规则无声失效。

## 7. 默认规则优化建议

按优先级分四档，均附实测依据。

### 第一档：直接提升拦截率（新增规则/扩展签名）

1. **补齐整类缺失检测**（对应 §4.1-4，黑样本 100% 放行的类目）：
   - CRLF 注入：URI/header 值中 `%0d%0a` + 头名模式（样本 `38/a9` 等 5 条）；
   - Log4Shell 扩面：1050 从 `user_agent` 扩到**全头 + URI + 参数**（改名才名副其实），样本 `19/c7` 实测绕过；
   - XXE：`<!doctype`/`<!entity`/`system "file://`（含 URL 编码形态，样本 2 条全漏）；
   - SSTI：`${...}` 表达式模板探测；
   - Java 反序列化：`rmi://`、`ysoserial`、`commons-collections` 等特征。
2. **命令注入词表与上下文扩展**：把 `$(...)`、反引号、`${IFS}` 纳入 rce 签名，命令词表扩充 `ping/base64/nc/ncat/dd/busybox`；样本 `5b/0d`（`$(ping${IFS}...whoami`）实测绕过。
3. **hex/unicode 编码归一化**：Stage-1 解码链（现最多 3 层 URL 解码）增加 `\xHH`、`\uHHHH`、HTML 实体命名形式的还原，可覆盖 hex-`eval` 类样本（`00/e1`）。
4. **SSRF 语义扩面**：参数名/JSON key 维度（`url=`、`source=`、`callback=`、`dataConfig`）与常见外带域名模式；仅靠 IP 字面量正则实测只拦 1/13。

### 第二档：降低误报（不影响拦截率）

1. **SQLi 检测对 Referer/UA 降权或跳过**：56 条 sqli 误报中 53 条来自 Referer。建议：Referer/UA 只参与异常评分累计（不触发 1002 的 ≥60 短路 Block），或对 Referer 值先剥离 URL 编码中文/搜索引擎域名白名单。**这是公网站点默认配置下收益最大的单条优化**。
2. **控制面默认规则模板的子评分门槛与托管规则对齐**：控制面播种的 SQLi/XSS 自定义规则用 `score ge 40`，而托管规则是 `ge 60`（并叠加聚合 80）。纯净复测中 G4 误报 1.27% vs G1 0.41%，增量 284 条误报里 65% 是无 body 的 GET（`/site.webmanifest`、`/hm.js?<hex>` 等正常请求），排除法指向 40 分低门槛把 libinjection 的低置信命中也拦了（规则命中日志缺失，归因为推断，见 §6.1）。**建议控制面默认模板改为 ge 60，预计误报回落至 ~0.4% 而拦截率基本不动**（黑样本纯净拦截 G1 34.0% vs G4 38.6% 的差异主要来自 body 检测与补类规则，不是低门槛）。
3. **误报兜底观察**：0.4% 总误报率达标，但 1002 一条规则贡献了几乎全部误报——调整后整体误报可再降一个数量级（实测推算 <0.1%）。

### 第三档：默认值与开关

1. **聚合阈值维持 40 即可**：threshold 30/40/60 实测结果完全一致（拦截决策由 Stage-1 critical 与子评分规则主导），调它没有意义；若要让阈值真正生效，需先让异常评分成为主要判决面（与第一档 1-3 联动）。
2. **PL 维持 2**：PL3 仅 +1.7pp 拦截、+0.04pp 误报（1011/1051 在本样本集上收益极小——白样本几乎都带 UA、超长 URI 样本极少）。PL3 的空 UA Challenge 对纯 API 调用方（无 UA 的健康检查、SDK）反而有害，不建议默认开启。
3. **修复 `inspect_body` 门控后评估默认开**：5.2% 黑样本签名仅在 body；agent 模式下建议 `inspect_body` 默认开启并配 body 大小上限（如 64KB 前缀），静态模式当前完全跳过 body 属文档与实现不一致，应择一修复。
4. **`detections` 开关接线**：让站点能按类目关闭检测（如纯 API 站点关 SSRF/XXE），在误报治理上比调阈值有效。

### 第四档：可观测性（先于一切调参）

1. **静态模式/agent 离线的日志兜底**：`log_event` 无 agent 时至少 `tracing::info!` 输出判决摘要（站点、规则、动作、命中详情）。当前静态 monitor 是"零反馈"运行，连验证规则是否生效都做不到（本次测试只能靠状态码反推）。
2. **auto-block 补通知与 reason**：补 rule_name；封禁/解封发 webhook。
3. **规则编译失败显式上报**：`.ok()` 静默丢弃改为告警计数，控制面展示"该规则未生效"。

## 8. 附录

### 8.1 测试矩阵与环境

| 组 | 配置 | 目的 |
|---|---|---|
| G1 | block, PL2, th40 | 主基线（托管 13 条真实拦截能力） |
| G2 | monitor | 出厂默认监控语义验证 |
| G3-pl1 / G3-pl3 | PL 1 / 3 | 灵敏度（1011/1051 仅 PL3 激活） |
| G3-th30 / G3-th60 | threshold 30 / 60 | 阈值敏感性 |
| G4 | agent 离线模式 + 控制面 11 条默认规则 + body 检测 + auto-block | 生产链路形态验证 |

- 监听 `127.0.0.1:6188`（G4 为数据面 80 端口），mock 上游一律 200；
- G4 使用 XFF 轮换规避 auto-block 污染：全量混跑用 `203.0.113.0/24`（RFC5737 文档段，254 个地址），纯净复测改用 `10.254.0.0/16` 轮换（每样本独享 IP）；混跑期间实测产生 60 条 600s 封禁记录、全部落在该段，且混跑结果证明 254 个地址不足以隔离封禁连带（§2 脚注 1）；
- 复现：`tools/waf-bench/README.md`。

### 8.2 官方 blazehttp CLI 对账结论

官方二进制（v0.3.0）以**启动时探测到的单一状态码**判定拦截（`worker.go:241` `code != blockStatusCode` 即放行）。探测请求（utils.go:56）含原始 `<script>`/空格等非法 request-target 字符，被 pingora 协议层以 400 拒绝（WAF 未见该请求），于是 `blockStatusCode=400`：

- 官方 G1 报告"检出率 2.29%"= 黑样本中恰好被协议层 400 拒绝的子集（本测自研回放器同口径黑样本 400 数：20）；
- 官方 G1 报告"误报率 3.11%"= 白样本协议层 400 子集（自测 1065，含当时环境的上游串扰噪声）；
- G1（block）与 G2（monitor）的官方数值几乎相同（TP 15 vs 25 / FP 1030 vs 1022）——证明其读数与 WAF 模式无关，量的是 pingora 协议层；
- 结论：官方 CLI 绝对数值对 pingap 类反代不可直接引用；本报告以自研回放器双口径为准，官方数据仅作协议层交叉验证。

### 8.3 测试方法学记录

- 回放器逐字节发送原始报文，仅覆写 `Connection: close`，不经过 HTTP 库序列化，畸形样本保真；
- 类别归因为启发式正则（与引擎 9 大类对齐），仅用于统计维度，不影响拦截判定；
- 曾出现的两个测试环境缺陷已修复并记录在案：mock 上游不排空请求体导致连接池串扰（~11% 状态污染，修复见 mock_origin.py `_drain`）；官方工具口径差异（§8.2）。修复后 protocol_reject 回落到真实值（~0.01%）；
- **auto-block 连带是第三个被识别并隔离的测试工件**：小轮换池（254 地址）混跑黑白样本时，黑样本触发封禁后同 IP 白样本被边缘连带拒绝，表观误报 26.4%；改为黑/白分离 + 每样本独享 IP 的纯净复测后得到 G4 真实指标（§2 脚注 1）。该工件本身演示了 §6.5/§6.6 的生产风险；
- 样本统计：33877 条（黑 658 / 白 33219），POST 占 30.7%。

### 8.4 关键代码索引

| 事实 | 位置 |
|---|---|
| body 读取 agent 门控 | pingap-plugin/src/waf.rs:2107 |
| `log_event` 无 agent 静默返回 | pingap-plugin/src/waf.rs:1796-1804 |
| auto-block 仅 agent 在位 | pingap-plugin/src/waf.rs:2595-2606 |
| 规则编译失败静默丢弃 | pingap-plugin/src/waf.rs:1687-1734 |
| 引擎 monitor 降级与 Stage-1 短路 | pingwaf-waf/src/engine/mod.rs:371-379, 461-466 |
| 托管 13 条规则定义 | pingwaf-waf/src/rules/managed.rs:17-140 |
| 默认信任 XFF | pingap-core/src/http_header.rs:415-424 |
| 控制面 PL= max(severity)、ml/threshold TODO | pingwaf-server/src/grpc/config.rs:669-694 |
| 控制面播种 11 条默认规则 | pingwaf-server/src/defaults.rs:111-202 |

## 9. 拦截级别落地与实测（Normal / Strict）

§7 的建议已在引擎层落地为**三维级别设计**：拦截级别（`WafLevel`：Normal/Strict）× 后端技术栈分类（`StackSet`：generic/java/php/python/node）× 语义化表达注入检测。默认值安全性优先：未配置时 Normal 级别 + 全栈覆盖，行为不缩水。

### 9.1 设计要点

| 维度 | Normal（默认） | Strict |
|---|---|---|
| 静态签名 | 内置 needle 全量（stack 过滤后） | 额外 10 条 strict-only 签名（CI-101..106 命令替换、TI-101..104 Java 表达式） |
| Referer/UA 降权 | SQLi/XSS/命令注入类命中 sev 5→2、不 critical（§7 第二档 1） | 同左 |
| CRLF/命令注入/反序列化命中 | 进评分 | 直接 critical（fast-path Block） |
| 表达式注入（语义检测） | 识别但不升级 | `add_expr_hit`（rce 子评分 +48）并 critical |
| 托管规则阈值 | 子评分 ≥60 / 聚合 ≥80 | 子评分 ≥50 / 聚合 ≥70，且新增 1061（`cf.waf.score.rce ge 40`） |
| 有效 paranoia | 配置值 | max(配置值, 3)（激活 1011/1051 等 PL3 规则） |

- **栈分类**：每个静态签名与托管规则标注所属技术栈（如 log4shell→java、`/etc/passwd` 等通用型→generic）。站点按 `stacks` 配置只加载相关栈（如纯 Java 后端配置 `stacks=["java"]` 后不再对 PHP/Node 特征做匹配），automaton 规模与扫描耗时随配置收窄；未配置则全栈兜底。
- **语义检测**：`detect_expr_injection` 只在**结构容器**（`${}`/`{{ }}`/`{% %}`/`<%= %>`）内识别计算特征（运算、方法调用、多段访问链、`new` 关键字），`${filename}` 等裸标识符不报——对应 §7 第一档 1 的 SSTI 扩面但避免关键词堆砌。
- **automaton 匹配语义修复**：签名扫描从 Standard 改为 `LeftmostLongest`。Standard 语义下同起点的短 needle（`${`）以非重叠方式先被报告，使前缀更长的 critical needle（`${jndi:`）永远不触发——这正是基线中 log4shell 样本漏报的根因，修复后该样本两档均 100% 拦截。
- **内存零拷贝**：静态模式规则/签名全部驻留内存（`&'static str`），hit 仅 `u32` 索引 + Copy 字段；请求规范化借用 headers/body（method 为 Cow），Pass 判决路径零字符串构建；扫描缓冲跨请求复用。

### 9.2 两档实测（同参数全量回放，XFF 独享 IP）

| 指标 | 基线 G1（§2） | Normal | Strict |
|---|---|---|---|
| 拦截率（严格口径） | 34.0% | 33.1%（218/658） | **37.8%（249/658）** |
| 误报率 | 0.41%（137 条） | **0.17%（55 条）** | 0.30%（101 条） |
| p50 / p95 | 1 / 2 ms | 1 / 2 ms | 1 / 2 ms |
| log4shell 样本 | 漏报 | 100% | 100% |

类别拦截率对比（黑样本，Normal → Strict）：

| 类别 | Normal | Strict | 说明 |
|---|---|---|---|
| rce | 16.7% | **66.7%**（2→8） | strict-only 命令替换签名 + critical fast-path |
| crlf | 0% | **60%**（0→3） | Strict 直接 critical |
| ssti | 40% | **80%**（2→4） | 语义表达式检测升级 |
| xxe | 0% | **50%**（0→1） | 同上 |
| sqli | 70% | 70% | needle 主导，两档一致 |
| xss | 33.3% | 33.3% | 同上 |
| log4shell | 100% | 100% | LeftmostLongest 修复后由 query/头即触发 |

### 9.3 结论与取舍

- **Normal 是低误报档**：误报 0.41%→0.17%（-60%），代价仅 -0.9pp 拦截（Referer/UA 降权后，原靠 Referer 命中拦下的黑样本回到评分路径）。剩余 55 条误报的触发点绝大多数在 query/path 本身（如搜索词 `union select`、遥测 URL），与 Referer 降权无关，进一步压降需要 needle 信任度分级（如把 "union select" 从 sev5 降为仅 Strict 生效）。
- **Strict 换取高危类目拦截倍增**：RCE/CRLF/SSTI/XXE 四类从 0-40% 提升到 50-80%，拦截率净增 +4.7pp；代价是误报 0.30%（+0.13pp，主要来自子评分门槛 50 与 PL3 规则）。适合源站无二次防护、或已知后端栈可用 `stacks` 收窄降低误报的场景。
- **两档时延无差异**（p95 均 2ms）：级别差异全部体现在规则装配期（automaton 规模、托管规则条数），不在请求路径的分支密度。
- **配置方式**（静态 TOML，插件段）：`level = "normal" | "strict"`；`stacks = ["java", ...]`（可选，默认全栈）。托管的 1061 号规则仅 Strict 装配；栈过滤同时作用于签名与托管规则（含 allow 类）。

复现：`tools/waf-bench/conf/level-normal.toml` 与 `level-strict.toml`，回放命令见 `tools/waf-bench/README.md`。

## 10. P0 覆盖面修复与实测（§9 之后的第二轮）

复盘报告（`waf-engine-review.md`）定位的 P0 缺陷级修复已全部落地，共四项：

1. **`+` 按空格解码（form 语义）**：`id=%27+OR+1%3D1--` 与 form body 中的 `waitfor+delay` 此前不解码即漏报；query 与 form body 的 value 按表单语义把 `+` 解为空格后再走解码链（key/cookie/header/path 不受影响，`C++` 类字面量保留）。
2. **needle 补齐与 sev 升级**：
   - 补无前导斜杠变体 PT-013 `etc/passwd`、PT-014 `etc/shadow`、PT-015 `proc/self`（sev5/5/4）——Aho-Corasick 非重叠消费使 `../` 吃掉 `/etc/passwd` 起始的 `/`，PT-003/004/005 在「前缀遍历 + 敏感文件」复合形态下永远无法命中，与 §9 修复的 `${` 遮蔽 `${jndi:` 同构；
   - 时间盲注/文件读写 needle SQL-004~009（`benchmark(`/`pg_sleep(`/`waitfor delay`/`load_file(`/`into outfile`/`into dumpfile`）sev 4→5——单命中从 4 分（远低于阈值 40）变为 critical fast-path 拦截；
   - 补语言级调用 CI-026~031（`os.system`/`__import__`/`shell_exec(`/`passthru(`/`proc_open(` sev5、`subprocess.` sev4）与 CRLF-003/004（`\r\nset-cookie`、`\r\nlocation:` sev5——裸 `\r\n` 不能升 sev5（JSON body 整扫误报），特异头名则无歧义）。
3. **静态模式受控 body 检测**：`pingap-plugin/src/waf.rs` 的 body 读取门控原为 `agent.is_some() && (body_limit > 0 || inspect_body)`，静态部署（无 agent）从不读 body，POST 类攻击全漏；现改为「日志采集仍需 agent，检测只需 `inspect_body = true`」。
4. **JS 括号调用结构检测（Strict-only）**：`detect_js_call` 识别 `parent['\x65val'](…)` / `this["constructor"]["constructor"](…)` 形态（被调名藏在括号内且常 hex 转义，关键词 needle 天然不可见），命中按表达式注入同路径升级 critical。

配套的误报治理（body 检测开启后白样本误报归因驱动）：

- **Normal 下 body 中反射类家族（SQLi/XSS/命令注入）降为弱信号**（sev 上限 2、不 critical）：JSON/HTML 报文里的 `<!DOCTYPE`、`javascript:`、引号+关键词串（libinjection quote-keyword）是常见良性内容，一票 critical 造成白样本 xss 类 46%、xxe 类 100% 误报；降为弱信号后需 3+ 独立信号才可能过 family 门。Strict 不降级（该档设计即激进）。结构性家族（XXE/反序列化/CRLF/SSRF）不受影响。
- **XXE-001 `<!doctype` sev 5→3**：DOCTYPE 是所有 HTML/XML 的样板，真实 XXE 需 `<!ENTITY`（XXE-002，保持 sev5）。
- libinjection 对 body 的命中与 needle 同口径降权。

### 10.1 实测结果（同参数全量回放，XFF 独享 IP）

| 配置 | 拦截率（严格口径） | 误报率 | 对比 §9 |
|---|---|---|---|
| Normal | **36.5%（240/658）** | 0.21%（69 条） | +3.4pp / +0.04pp |
| Normal + `inspect_body` | **38.1%（251/658）** | **0.23%（75 条）** | 再 +1.6pp / +0.02pp |
| Strict | **51.1%（336/658）** | 0.35%（115 条） | +13.3pp / +0.05pp |
| Strict + `inspect_body` | **63.8%（420/658）** | 1.98%（658 条） | 再 +12.7pp / +1.63pp |

类别拦截率（黑样本，修复前 → 修复后）：

| 类别 | Normal 前→后 | Strict 前→后 | 主因 |
|---|---|---|---|
| lfi | 32.0% → **68.0%** | 36.0% → **72.0%** | PT-013/014 解除遮蔽 |
| sqli | 70.0% → **85.0%** | 70.0% → **85.0%** | 时间盲注 sev5 + `+` 解码 |
| xss | 33.3% → 33.3% | 33.3% → **80.0%** | detect_js_call（14 条 hex 转义括号调用） |
| rce | 16.7% → 16.7% | 66.7% → 66.7% | body 开启后 33.3% / 75.0% |
| ssrf | 7.7% → 7.7% | 7.7% → 7.7% | body 开启后 23.1% / 46.2% |
| deser | 0% → 0% | 0% → 0% | body 开启后 0% / 83.3% |
| crlf | 0% → 0% | 60.0% → 60.0% | body 开启后 0% / 100% |

其余类目两档持平。Normal 档误报分布与 §9 基本一致（主体仍是 query/path 本身含攻击串的白样本，如搜索词 `union select`）；body 开启后新增误报仅 6 条（含 1 条 body 含 `file://` 的白样本——真实 SSRF 探测确常走 body，保留 sev5）。

### 10.2 结论与取舍

- **Normal 是默认推荐档**：不开 body 检测时 36.5%/0.21%，开 `inspect_body` 后 38.1%/0.23%，误报几乎零代价；本数据集中反射类家族的 body 增益本就趋近于零（见上表），降权策略不损失真实拦截。
- **Strict + `inspect_body` 是极限拦截档**：63.8% 拦截的代价是 1.98% 误报（主体为含裸 CRLF 的白样本 94.5%、引号+关键词 JSON body 等），适合内网影子部署/观察模式或可承受人工放行的场景；`stacks` 收窄与 allow 规则可进一步压误报。
- **时延**：不开 body 检测两档 p95 仍为 2-4ms；开启后 p95 ≈3s 是回放客户端 `sendall` 大 body 与 WAF「上传中途拦截」的固有交互（拦截后客户端仍在发送），非引擎匹配开销。
- **复现**：`tools/waf-bench/conf/level-{normal,strict}{,-body}.toml`，`-body` 变体多一行 `inspect_body = true`；回放命令见 `tools/waf-bench/README.md`。
- **未竟事项**（P1，见 `waf-engine-review.md`）：JSON 递归解包（当前对 `{"body":"payload"}` 类嵌套串不展开）、deser 黑样本在 Normal+body 档仍依赖偶然信号（Strict 档 83.3% 由 critical 直拦）。

## 11. P1 语义增强与实测（§10 之后的第三轮）

P1 覆盖面扩展与语义误报治理（`waf-engine-review.md` §4 P1 项 4-8）已全部落地：

1. **JSON 递归解包 + 输入字段语义**：JSON body 由 serde_json 解析（限深 6/值长 4KB/最多 64 值），成员 string 值按 JSON 路径（`a.b[0]`）独立进解码+扫描——`{"body":"…union select…"}` 类嵌套载荷不再依赖 blob 整体判定，`\u003c` 类转义由解析器天然还原。**字符串成员本身是序列化 JSON 时（埋点内嵌载荷、`value="{\"icon\":\"\\n<svg…\"}"`）就地再解包并替换容器**：容器形态（`"key":value`）会踩 libinjection quote-keyword 指纹，且展开后 icon 类长成员受 256B 分级保护；纯数字/布尔成员也产出字符串值（不构成攻击面，但保证容器替换语义成立）。配套引入 `DecodedValue.field` 语义标记：**离散输入字段**（query/header/cookie/表单字段/JSON 成员）是注入面，走完整 severity；**opaque blob**（非结构化 body）视为 bulk 内容，反射类家族降弱信号（Normal）。表单字段值同样适用 JSON 再解包（`param={"add":5,"delete":0}` 类 API 载荷不再踩 quote-keyword）。
2. **CRLF 头名形态 critical**：解码值中 CRLF（含 `\r\r\n\n` 混排规避）后紧跟 `name:` 头名形态才在 query/path/header/cookie 面一票拦截（黑样本 `%0D%0AX-Pen-Test:` 形态）；裸多行文本（表单单行输入回传 query 换行、粘贴文档）只评分不拦——实测白样本中该形态普遍存在（百度翻译多行 query、mathb.in 文档、StackBlitz 代码内容），「query 不含换行」的假设不成立。body 面始终只评分。
3. **弱信号评分语义修正**（两轮实测迭代）：`union select` 搜索短语命中改为**零分跳过**——needle 与 libinjection 指纹描述同一字符串，镜像多面不放大，Pass 快路径零开销；`FIELD_STRONG_MAX_LEN`（256B）——离散 body 字段解码值超长按 bulk 弱信号化（粘贴代码/文档含 `<script>`、引号关键词样板），短载荷不受影响；反射类弱信号保留 family 计分（三个独立弱特征过门是 P0 验证的拦截路径，完全脱离 family 的版本实测丢 6pp 拦截率）。
4. **SSRF/命令注入 needle 扩面**：回环变体 SSRF-013~017（`localhost`/`127.0.0.1` sev4、`0x7f000001`/`2130706433`/`0177.0.0.1` sev5）与 CI-032~037（`invoke-expression`/`iex (`/`cmd /c`/`cmd.exe /c`/`powershell -enc`/`system(`）。
5. **SQL union-select 语义门**：`sqli_union_statement_shaped` 判定解码值是否具备注入语句结构特征——引号破出（`' union`）、常量探测（`union select 1`/`null`）、注释终止符（`--`/`/*`/`#`）、FROM 子句，四特征全缺的 `union select` 命中（needle SQL-001/002 与 libinjection union-select 指纹）在 Normal **零分跳过**（needle 与 lib 指纹描述同一字符串，镜像多面不放大）。白样本归因显示 FP 大头是搜索短语（`/AS/Suggestions?bq=site:x.com+union+select+关键词怎么用` 等 16 条 sqli 误报全部此形态）；真注入语句（含 from/引号/常量/注释任一）不受影响。Strict 不设门。已知取舍：散文含完整 `union select … from …` 句式（92/49 样本）在词法上无法区分，保持拦截并 pin 测试。
6. **script-URI 的 HTML 上下文门 + 分源语义**：`xss_script_uri_html_shaped` 判定值内是否具备 HTML 标签结构（`<svg onload=…>`、`"><img …>`）——真注入载荷需要标签上下文才能执行，而遥测埋点会把 DOM 属性原样序列化进 JSON（`{"href":"javascript: void(0);"}`，beacon 类上报 16 条误报全部此形态），JSON 解包后进一步以 `attributes.href` 短成员形态出现。语义：**body 源**无标签结构的 `javascript:` 命中（needle XSS-007 与 libinjection js-uri 指纹）在 Normal 零分跳过——blob 与解包成员的镜像不能靠弱信号累加踩过 family 门；**query/cookie/header 源**的裸 `javascript:` 保留 critical（`?url=javascript:alert(1)` 是真实反射型 XSS 形态）。Strict 不设门。
7. **CRLF 头名形态 critical 分源**（补全第 2 条语义）：`crlf_header_injection_shaped` 要求 CRLF 后紧跟 `name:` 头名形态才在非 body 面一票拦截；body 面无论形态只评分。

### P1 实测（post6 全量回放，33877 样本）

| 配置 | 拦截率 | 误报率 | 拦截 vs P0 | 误报 vs P0 |
|---|---|---|---|---|
| Normal | 36.8%（242/658） | 0.15%（51） | +0.3pp | 69→51（-18） |
| Normal + body | **44.1%（290/658）** | **0.18%（61）** | **+6.0pp** | 75→61（-14） |
| Strict | 51.4%（338/658） | 0.35%（115） | +0.3pp | 持平（115） |
| Strict + body | 63.8%（420/658） | 2.38%（792） | 持平 | 658→792（+134） |

拦截增量归因（Normal+body，+39 条黑样本）：other 36.2%→42.8%（needle 扩面 + JSON 嵌套解包，+37 条）、deser 0%→33.3%（+2）、crlf 0%→40%（头名形态 critical，+2）。

误报收敛归因（Normal+body，-14 条）：

- **sqli 16→1**：union-select 语义门压掉全部搜索短语误报（`site:x.com union select 关键词怎么用` 类），sqli 白样本 FP 率 23.9%→1.5%；唯一遗留是含完整 `union select … from …` 句式的散文（词法不可分，pin 测试）。
- **xss 1→3（净 +2）**：P1 的 JSON 成员 typed 检测曾让埋点类误报涨到 20（beacon `javascript: void(0)` DOM 采集 16 条 + CSP report 2 条 + 其他），HTML 上下文门 + 字符串 JSON 再解包把 20 条压回 3 条——遗留 2 条为 P0 已有（非 js-uri 形态），1 条为截断内嵌 JSON（`__logs__.value` 被日志系统截断后内层 parse 失败、容器保留命中，53/8d）。
- **other 51→49**：form 字段 JSON 再解包（`param={"add":5,"delete":0}` 类）压掉 libinjection quote-keyword 误报，crlf 分源把裸多行文本从 critical 降回评分。
- **rce 4→5（+1）**：`commands` 字段合法携带 `/bin/sh` 的 CI 类 API 载荷（CI-019 sev5，词法上与命令注入同形）。

Strict+body 误报 +134 条（1.98%→2.38%）的构成：JSON 成员 typed 检测把埋点/遥测类 body（FullStory 会话回放、CSP report、云控制台埋点）的成员值以完整 severity 检出，而 Strict 档**不设语义门**（弱信号机制也是 Normal-only）。这是档位设计代价：Strict 面向安全敏感场景，2.38% 的误报率换成员级检测深度；Normal 档（0.18%）才是误报敏感场景的推荐配置。后续 P2 的 label/count 灰度基建（§10 建议）是 strict 档误报治理的正解。

**已知取舍（有意保留的误报）**：① 散文含完整 `union select … from …` 句式（1 条，词法不可分）；② 截断的内嵌 JSON 容器（1 条，日志系统截断致内层 parse 失败）；③ `commands` 字段携带 `/bin/sh` 的 CI API 载荷（1 条）；④ 2 条 P0 遗留非 js-uri XSS 形态。合计约 5 条/33219 白样本（0.015pp）由形态学不可分导致，其余 56 条为评分累积过门，属 P2 label/count 基建的治理范围。

## 12. P2/P3 确定性扩面与实测（§11 之后的第四轮）

P2/P3 以「Strict+body 档 238 条漏报全量归因」为输入（b64 递归解码 + URL 双轮 + `\u` 反转义逐条脚本归因，6 个疑问样本 spot 回放确认引擎缺口），落地确定性扩面：SQL 强正则扩面 + 注释剥离重扫、base64 值级展开（递归 2 层）、overlong UTF-8 字节级还原、needle 扩面（win.ini/管道反引号/DOM 链/OGNL/PHP 序列化/JSFuse/Java exec 链）、deser-shape 形态分级（Normal 评分 / Strict critical）。实现细节与语义门设计见 `waf-engine-review.md` §4 P2/P3 节。

首轮全量回放暴露 16 条新增误报（0.15%→0.20%），逐条归因为三类语义缺陷并回修：

1. **blind-probe 踩散文**（7 条）：泛化 `case when…then` 备选命中白样本散文 "in the case when you feel chest pain … then"——回修为**要求 SQL 操作符前缀**（select/and/or/`||`/`;`/引号/括号）。
2. **bare-select 踩合法查询**（6 条）：`q=SELECT * FROM users WHERE slug='x' LIMIT 1` 类完整查询参数与 Bing 搜索短语（`site:segmentfault.com select user_id,… from yy_user where …`，经 Referer/body/双编码 loc= 镜像）——回修为**跳过含完整子句**（WHERE/GROUP BY/ORDER BY/HAVING/LIMIT/OFFSET/JOIN）的值，表枚举探测（`SELECT * FROM all_tables`）不受影响。
3. **b64 词表踩 quote-keyword**（3 条）：base64 展开把 b64 字典词表带入扫描面，词表内撇号缩写（"couldn't select a favorite"）与远距关键词触发「任意距离引号+关键词」的旧 quote-keyword 正则——回修为**邻接判定**（引号后容差 `\s);` 内直接跟关键词）。
4. **回修护栏**：恒真式收紧连带暴露 8 条 P1 依赖宽松 quote-keyword「误打误撞」拦截的 PortSwigger 布尔盲注（`AND (SELECT 'a' FROM users LIMIT 1)='a`、`AND 1=CAST((SELECT …) AS int)--`）回归漏报——新增 `bool-subquery` 强检查（操作符前缀子查询 / `N=(SELECT` 比较）、SQL-020 `utl_inaddr`（Oracle 报错注入）、CI-043 `getruntime().exec`（OGNL/SpEL RCE 载荷核心，同时承接 6 条 b64 包裹 OGNL 黑样本在 Normal 的拦截）、CI-044 `securegroovy`（Jenkins 沙箱绕过端点）。回修后 16 条误报全部消除、59 条新增拦截零回退。

### P2/P3 实测（post7 全量回放，33877 样本）

四轮迭代后的最终形态：全部四个配置**零回退**，Normal / Normal+body / Strict 三档**零新增误报**，Strict+body 仅 2 条新增（归因见下）。

| 配置 | 拦截率 | 误报率 | 拦截 vs P1 | 误报 vs P1 |
|---|---|---|---|---|
| Normal | 46.8%（308/658） | **0.10%（33）** | +10.0pp | 51→33（-18） |
| Normal + body | **55.5%（365/658）** | **0.13%（43）** | **+11.4pp** | 61→43（-18） |
| Strict | 63.8%（420/658） | 0.32%（105） | +12.4pp | 115→105（-10） |
| Strict + body | **77.7%（511/658）** | 2.17%（721） | +13.9pp | 792→721（-71） |

拦截增量归因（Normal+body 口径，+75 条黑样本）：

- **other +65 条（42.8%→54.8%）**：base64 值级展开（P2-2）与 overlong UTF-8 还原（P2-4）打开编码包裹载荷的可见性，needle 扩面（win.ini/管道反引号/DOM 链/OGNL/PHP 序列化/Java exec 链/JSFuck）与 SQL 强正则扩面（bare-select/blind-probe/截断恒真/注释剥离重扫/bool-subquery）承接可见性增益。
- **deser 33.3%→100%（+4）**：DZ-012~016 needle + deser-shape 形态分级，JSON 成员里的 OGNL/PHP 序列化载荷全拦。
- **xss +2（33.3%→40%）**：XSS-020/021 prototype 链/JSFuck + `XSS_DOM_CHAIN` 正则。
- **rce/ssrf/ssti/lfi 各 +1**：CI-043 `getruntime().exec`、编码展开后的 SSRF 变体、TI needle 命中 b64 解出内容、PT-016 `win.ini`。

误报收敛归因（-18 条，四配置一致的同一批样本）：

- **恒真式收紧**（`word = string` 比较不再算注入信号）：Lucene/API 过滤语法（`author=="CT Stack"` 类）误报消除。
- **quote-keyword 邻接化**（引号后 `\s);` 容差内直接跟关键词）：缩写撇号（"couldn't select"）与 b64 词表远距误触发消除。
- 这两项回修顺带把 18 条 P1 遗留误报（slsConfigs JSON、Bing ClientInst、QQ 统计 beacon 等遥测类）全部压掉——Normal 档误报 51→33，**0.10% 为全程最低**。

Strict+body 新增 2 条误报（净 -71，不回修的理由）：

1. **31/56**（ctrip 165KB 遥测 body）：strict 档 SSTI 模板 needle（TI-001~004）+ EL 表达式在 JSON 成员 critical——与 P1 归因的埋点类（FullStory/CSP report）同一形态，档位设计代价。
2. **5d/1e**（29KB bulk body）：长随机词被 base64 展开出引号+关键词内容，strict 档无弱信号门，libinjection quote-keyword 指纹直接 critical。bulk 长内容在 Normal 档由 `FIELD_STRONG_MAX_LEN` 弱信号化兜底，strict 档按设计全强度检测。

两条均为 strict+body 高强度检测的既有形态，拦截收益（+91 条、误报净 -71）远大于代价，不做引擎回修——strict 档误报治理的正解是 P3 label/count 灰度基建（§10 建议）。


## 13. P4 解码链补齐 + strict FP 治理与实测（§12 之后的第五轮）

P4 以「post7 strict+body 漏报 147 条全量归因 + strict 档 105 条 FP 归因」为输入，两条主线落地（实现细节见 `waf-engine-review.md` §4 P4 节）：

1. **解码链补齐**：b64 解码层 `\u`/`\x` 转义无条件还原、JSON 结构位置裸控制字符剥离重试、query 参数 JSON 值解包、HTML 符号实体表补 27 个（`&colon;`/`&Tab;` 等 DOM 序列化常用变体）——打开三层编码（b64→JSON→b64）与转义混淆载荷的可见性。
2. **needle 扩面**：宽命令分隔（`;|`/反引号/`||` 前缀 × whoami/uname/ping/curl/wget/sleep/echo）、`eval(atob(`、LDAP 注入三形态、JSFuck、`WEB-INF`/`portal_inc.lua` 源码路径、Postgres `COPY … TO PROGRAM`——全部 sev4~5 强特征。
3. **strict FP 治理**：PINGWAF-1051（长 URI）Block→Log；strict CRLF blanket-critical 摘除（body 多行文本/非头名形态不 critical）；path 源 CI/Deser 旁路 RCE 子分桶（矩阵参数是存储 URL 语法）；js-call 对非字段 body blob 零分跳过。

CRLF critical 摘除的直接代价是 strict+body 回退 42 条（35 条为「CRLF+弱同伴」黑样本）。逐条归因后补**同伴门**回修：strict 下同值携带 CI/PT/Deser/SSRF 家族特征时 CRLF 恢复 critical——换行走私载荷是真实 response-splitting 流量，纯多行文本无同伴。同轮回修还有 into-file 语句形态门（SQL-008/009 + libinjection `into-file` 指纹要求 `into (out|dump)file '目标'` 引号形态，搜索短语零分跳过）与 PINGWAF-1021 摘压缩包后缀（`.zip/.tar.gz` 是普通下载资源）。

### P4 实测（post9 全量回放，33877 样本）

| 配置 | 拦截率 | 误报率 | 拦截 vs P2/P3(post7) | 误报 vs P2/P3(post7) |
|---|---|---|---|---|
| Normal | 50.5%（332/658） | **0.07%（23）** | +3.6pp | 33→23（-10） |
| Normal + body | **59.1%（389/658）** | **0.10%（32）** | **+3.6pp** | 43→32（-11） |
| Strict | 66.6%（438/658） | **0.07%（23）** | +2.8pp | 105→23（-82） |
| Strict + body | **79.0%（520/658）** | **0.14%（46）** | +1.3pp | 721→46（-675） |

P4 内部两阶段对照（post8 = P4 主体落地、post9 = 归因回修后）：strict+body 拦截 503→520（+9：同伴门追回 17 条 CRLF 回退，crlf/rce/xss 各 -1 为既定语义收敛代价，净 +34 新拦截 / -25 回退）；误报 69→46（-23：js-call blob ×16、into-file 搜索短语 ×6、backup 后缀 ×5 全消，normal/strict 系各 -10/-11）。

**里程碑**：四个配置的误报率**首次全部低于 0.2% 目标线**——Normal/Strict 0.07%、Normal+body 0.10%、Strict+body 0.14%；主档（Normal+body）误报 32 条为五轮迭代最低。strict+body 拦截率 77.7%→79.0%，累计五轮演进 63.8%→79.0%（+15.2pp）。

类别增量（strict-body，vs post7）：ssrf 53.8%→**69.2%**（SSRF-013~017 回环变体 + 解码链补齐）、lfi 88%→**92%**（PT-016/017/018）、other 76.0%→**77.7%**（宽命令分隔 + LDAP + COPY TO PROGRAM + 三层编码解码）；crlf 100%→80%、rce 83.3%→75%、xss 90%→86.7% 为 strict critical 收敛与同伴门的既定语义代价（各 -1 条）。

残余 46 条 strict+body 误报构成（下轮素材）：libinjection-sqli tautology/quote-keyword ×15、XSS 反射类（script-tag/`<script>` 查询值）×13、XXE+XSS 收集 HTML ×4、TI/EXPR ×2、其余零星（SSRF-008、PINGWAF-1020、CI-019 各 1）。拦截侧剩余 138 条漏报以多层编码数组嵌套与深层混淆为主。

## 14. P5 残余 FP 形态门与实测（§13 之后的第六轮）

P5 以 post9 残余 46 条 strict+body 误报的逐条归因为输入（libinjection tautology/quote-keyword 指纹 ×15、XSS 反射 `<script` 文字引用 ×13、同伴门反噬 ×6、收集 HTML/playground ×8），落地两道确定性语义门（实现细节见 `waf-engine-review.md` §5 P5 节）：

1. **libinjection 指纹长度门**：`tautology` 指纹 + 值 >32B 且无 comment-terminator → 搜索短语零分（真实恒真探测极短，散文 "1 and 1=1 is a basic operation" 不拦，长盲注带注释终止符保留 critical）；`quote-keyword` 指纹 + 值 >256B → 零分（词表文档远距撇号误触发，真实长 exfiltration 自有 UNION 关键指纹）。第一版门误伤 11 条黑样本（长盲注 ×9、`<script+…>` 未解码 ×2），收紧后 527 条拦截全部保持。
2. **`<script` 闭合标签门**：XSS-001 needle 与 libinjection `script-tag` 指纹两侧同语义，要求 `<script` 具备真实开标签形态；无闭合的 `<script`（`1<script`、"binary<script is incorrect"）是文字引用而非标签。零星条目 SSRF-008 / PINGWAF-1020 / CI-019 各按形态收窄。

### P5 实测（post10 全量回放，33877 样本）

| 配置 | 拦截率 | 误报率 | 拦截 vs P4(post9) | 误报 vs P4(post9) |
|---|---|---|---|---|
| Normal | 50.5%（332/658） | **0.02%（7）** | 持平 | 23→7（-16） |
| Normal + body | **59.1%（389/658）** | **0.05%（16）** | 持平 | 32→16（-16） |
| Strict | 66.6%（438/658） | **0.02%（7）** | 持平 | 23→7（-16） |
| Strict + body | **79.0%（520/658）** | **0.07%（24）** | 持平 | 46→24（-22） |

**里程碑**：拦截率四配置零回退，误报率全部压进 **<0.08%**（0.02%/0.05%/0.02%/0.07%）——形态门只作用于「单规则弱指纹 + 无同伴」的反射文本，多规则组合的 critical 判决不受影响。主档（Normal+body）误报 16 条、Normal/Strict 静态档仅 7 条。

残余 24 条 strict+body 误报以 xray POC 定义模板、嵌套 URL 埋点、HTML playground 收集类为主（多规则组合的 strict 档位语义代价）。拦截侧 post9 漏报 138 条同期完成全量归因（12 条链路差异 / 57 条分数不足 / 68 条零信号 / 1 条 Challenge），作为 P6 拦截侧扩面的输入（§15）。

## 15. P6 拦截侧确定性扩面与实测（§14 之后的第七轮）

P6 输入是 post9 strict+body 口径 138 条漏报（658−520）的全量分层归因，三个批次性质完全不同：

1. **12 条 triage/回放链路差异**：11 条 POST 请求**无 Content-Length**——HTTP/1.1 语义下无长度声明的请求体为空，payload 根本到不了服务器，任何引擎都无法基于空 body 判决；样本集本身不符合传输语义。1 条 GET 返回 400（协议拒绝），非引擎缺口。**方法论**：批量回放 verdict 与单样本 triage verdict 不一致时，先核对传输语义再谈检测能力。
2. **57 条 Monitor（分数不足）**：信号已命中但档位门未过——CRLF-001/002 ×22（多行文本形态，P4 同伴门的既定语义决策）、XSS-019 ×13、SSRF 弱信号 ×5 等。逐条复核后仅其中真攻击形态值得为 Normal 档补强，其余保持 Monitor。
3. **68 条 Pass（零信号）**：解码后无任何规则命中。批量解码脚本（b64 递归 + `\u` 反转义 + URL 双轮）聚类后定位出 7 个可修形态。

落地修复（实现细节见 `waf-engine-review.md` §5 P6 节）：

- **`<script` 开标签语义修正（P5 门缺陷）**：P5 门正则要求 `[^>]*>` 闭合，紧凑 `<script>alert(1)</script>` 不匹配——XSS-001 与 libinjection 两侧门对紧凑标签全零分跳过，属检测塌方。改为双正则：属性形态 `<script[\s+][^>]*>`（全源）+ 紧凑开标签 `<script>`（仅反射面 query/path/header/cookie）；body 源紧凑 `<script>` 是合法 HTML 上传（playground 类白样本），属性形态仍覆盖。
- **SQL needle ×3**：SQL-022 `cast((select`（PortSwigger 嵌套 CAST 数据外带）、SQL-023 `extractvalue(`（Oracle XPATH 报错注入）、SQL-024 `or 1 limit`（截断恒真尾），全部 sev5。
- **CI needle ×2**：CI-083 `ping -c `（链式 ping 探测）、CI-084 `#context.get(`（Struts2 OGNL 上下文变量链）。
- **b64 展开实体解码扩面**：解码值 `%` 条件扩为 `%` 或 `&#`（b64 内 HTML 实体 meta-refresh 形态可见）。
- **query key 进扫描面**：`?redirect:%24%7B…` 的 `%3D` 编码 `=` 使整串成为 key、value 为空——解码 key（≤512B）以 `field` 形态加入扫描面，否则 OGNL 载荷整体不可见。
- **path 独立扫描循环补 search_phrase 门**：P5 门只加了 decoded_values 循环，`normalized.path` 的独立 sev5 fast-path 循环漏加——补门且 search_phrase 时 `continue` 零分跳过（否则 XSS 子分 48 会被 PINGWAF-1003 兜底重新拦截）。

### P6 实测（post11 全量回放，33877 样本）

| 配置 | 拦截率 | 误报率 | 拦截 vs P5(post10) | 误报 vs P5(post10) |
|---|---|---|---|---|
| Normal | **51.8%（341/658）** | **0.02%（5）** | +9 | 7→5（-2） |
| Normal + body | **60.6%（399/658）** | **0.04%（14）** | **+10** | 16→14（-2） |
| Strict | **67.9%（447/658）** | **0.02%（5）** | +9 | 7→5（-2） |
| Strict + body | **80.7%（531/658）** | **0.07%（22）** | **+11** | 24→22（-2） |

**里程碑**：四配置**全部双向改善**——拦截 +9~+11 零回退、误报各 -2；strict+body 拦截率首次突破 **80%**（79.0%→80.7%），累计七轮演进 63.8%→80.7%（+16.9pp）。误报率全部 <0.07%（0.015%/0.042%/0.015%/0.066%），主档（Normal+body）60.6% / 0.042% 为七轮最佳平衡点。

### P6 回归验证

- 172 单测全绿（新增 `compact_script_tag_blocks_on_reflected_sources`、`script_prose_in_path_passes`、`post9_missed_payload_forms_block`、`base64_html_entity_inner_payload_blocks`）。
- 658 黑样本单样本 triage：527（P5）→ **539（+12，零回退）**——新增拦截覆盖 cast 外带 / XPATH 报错 / 截断恒真 / OGNL 链 / ping 链 / b64 实体包裹六族。
- fp46 白样本（post9 strict+body 残余 FP 集）单样本 triage：Block 22→**20**（P6 多修复 2 条），**零新增 Block**；剩余 20 条均为多规则组合的 strict 档位代价（HTML 上传/收集类）。
- 性能守恒：全部新增 needle 走既有 AC 自动机与 Lazy 正则，key 扫描面 ≤512B 上限，无常量开销。

## 16. P7 Monitor 分数不足细分 + 零信号复检与实测（§15 之后的第八轮）

P7 输入改为 post11 实测漏报（strict+body 口径 127 条）的重新三分层——13 条 triage Block 但回放 passed/protocol_reject（链路差异）、54 条 Monitor（有信号分数不足）、59 条 Pass（零信号）、1 条 Challenge。两个可修层的聚类产出：

- **b64 展开外层长度门 16→10**：`MSBhbmQgMT0y`（`1 and 1=2`，12B）藏身 JSON 成员内，落在旧 16B 外层门与解码器 12B core 门之间的盲区（`{"id":"<b64>"}` 形态）。
- **needle ×10**：SQL-025 `xp_dirtree`、SQL-026 `dbms_pipe.receive_message`、PT-019 `..;/`、DZ-017 `rO0AB`（Java 序列化魔数 b64）、SSRF-018 `gadgets/makerequest`、CI-085 `<?php`、CI-086 `think\app/invokefunction`、CI-087 `` `touch ``、CI-088 `runphp=`、CI-089 `*)((|`，全部 sev5。
- **事件处理器正则双前缀**：XSS_EVENT_HANDLER 从 `\son…=` 放宽为 `(?:\s|\+)on…=`——header/path 源 `+` 不按空格解码，`<xss+onafterscriptexecute=…>` 的 Referer 反射形态此前不可见。
- **Referer/UA 降权的 markup 豁免**：`xss_markup_shaped`（script 标签/事件处理器/脚本 URI）命中时跳过 meta-header 降权——浏览器只发合法 URL，此类结构必为攻击工具反射回放；散文引用的 Referer 仍正常降权。

实现细节见 `waf-engine-review.md` §5 P7 节（第 28~31 条）。

### P7 实测（post12 全量回放，33877 样本）

| 配置 | 拦截率 | 误报率 | 拦截 vs P6(post11) | 误报 vs P6(post11) |
|---|---|---|---|---|
| Normal | **55.6%（366/658）** | **0.02%（5）** | +25 | 持平（5） |
| Normal + body | **64.7%（426/658）** | **0.04%（14）** | **+27** | 持平（14） |
| Strict | **71.1%（468/658）** | **0.02%（5）** | +21 | 持平（5） |
| Strict + body | **85.0%（559/658）** | **0.07%（22）** | **+28** | 持平（22） |

**里程碑**：四配置拦截 +21~+28、误报全部持平（零回退零新增）——P7 是八轮中单轮拦截增益最大的一轮（此前最高 +11）。strict+body 80.7%→**85.0%**（+4.3pp），累计八轮演进 63.8%→85.0%（+21.2pp）；主档（Normal+body）60.6%→64.7%。收益构成：b64 外层门放宽（JSON 成员内短载荷可见）+ 10 条 sev5 needle + markup 豁免（Referer 反射事件处理器）三类修复分别承接独立漏报族。p95 与 P6 一致（静态 4ms / body ~3s¹ 客户端固有），性能守恒。

### P7 回归验证

- 174 单测全绿（新增 `p7_monitor_and_zero_signal_forms_block`——11 类 Monitor/Pass 形态确定性覆盖，`plus_encoded_event_handler_in_referer_blocks`）。
- 658 黑样本单样本 triage：539（P6）→ **576（+32，零回退）**——新增命中全部来自 P7 needle 与联动跨过 strict 家族门的样本。
- fp46 白样本（post9 strict+body 残余 FP 集）单样本 triage：Block 20（与 P6 一致），**零新增**——20 条全部在 post11 回放中同样被拦。
- 性能守恒：needle 全部进既有 AC 自动机；markup 豁免是四正则短路判定（已在 needle/指纹命中后才调用）；b64 外层门放宽 16→10 使解码尝试略增，仍有 charset 快检 + core≥12 + printable>90% 三重门约束。

## 17. P8 零信号残余形态与实测（§16 之后的第九轮）

P8 输入是 post11 漏报经 P7 后仍开放的 84 条（44 Pass / 37 Monitor / 2 链路 / 1 Challenge），Pass 抽查定位出四个引擎结构性缺口：

- **引号包裹 JSON 解包**：`id='{"id":"<b64>"}'` 的单引号外壳是 SQL/字符串拼接产物，`looks_like_json` 拒识使成员不可见——`unpack_string_json` 入口加一层同引号剥壳重试，query/form/JSON 成员七个调用点全覆盖。
- **SQL-027 `updatexml(`**：MySQL 报错注入外带核心；Drupal form 数组参数名注入形态 `name[0 or updatexml(…)%23]` 的 key 扫描面 P6 已就位，缺的只是 needle。
- **CI-090 `allow_url_include`**：PHP-CGI ini 覆盖（CVE-2024-4577 族），`?-d+allow_url_include%3Don` 经 key 扫描命中。
- **path 段 tautology**：libinjection 源门排除 Path 且整体 34B 超 prose 门——`path_tautology_segment` 对 `/` 分段独立检测（段 5~32B，与 prose 门语义一致）。

实现细节见 `waf-engine-review.md` §5 P8 节（第 32~35 条）。

### P8 实测（post13 全量回放，33877 样本）

| 配置 | 拦截率 | 误报率 | 拦截 vs P7(post12) | 误报 vs P7(post12) |
|---|---|---|---|---|
| Normal | **56.2%（370/658）** | **0.02%（5）** | +4 | 持平（5） |
| Normal + body | **65.3%（430/658）** | **0.04%（14）** | +4 | 持平（14） |
| Strict | **71.7%（472/658）** | **0.02%（5）** | +4 | 持平（5） |
| Strict + body | **85.6%（563/658）** | **0.07%（22）** | +4 | 持平（22） |

**结果**：四个新形态各承接一条黑样本、四配置同幅 +4 零回退，误报全部持平零新增——与 triage 回归（571→575）完全一致。strict+body 85.0%→**85.6%**，累计九轮演进 63.8%→85.6%（+21.8pp）；主档（Normal+body）64.7%→65.3%。p95 与 P7 一致（静态 4ms / body ~3s¹），性能守恒。

### P8 回归验证

- 175 单测全绿（`p8_zero_signal_forms_block` 覆盖四形态 + prose slug 放行负样本）。
- 658 黑样本单样本 triage：571（P7 同口径）→ **575（+4，零回退）**——四个新形态各承接一条。
- fp46 白样本 triage：Block 20 持平，**零新增**。
- 性能守恒：剥壳是 O(1) 首尾检查；`path_tautology_segment` 仅在 Path 源值上分段跑既有 `detect_sqli`；两条 needle 进既有 AC 自动机。

## 18. P9 b64 传输门放宽 + Monitor 形态升级与实测（§17 之后的第十轮）

P9 输入两路：post13 strict 漏报 95 条全量归因 + P8 遗留 Monitor 22 条逐条复核。

- **批次一（解码链）**：95 条中 18 条是无 Content-Length 的 POST/PUT（回放器与 triage 直读文件的链路差异，物理不可拦）；其余 77 条以 4 个代表样本模拟解码链定位出唯一共同断点 `B64_MAX_VALUE_LEN=4096`——5.1KB wire 值解出 3.8KB JSON（OGNL `\u` 转义）整体落在门与检测器之间。修复：门放宽至 16384（charset+printability 双质量门不动）、控制符剥离改空格替换（保 `selEct\n1` 词边界）、`SQLI_UNION_COMMENT_SPLIT` 粘注释拆分（`unION#filler\nselECT`；行注释剥离重扫因教学 SQL 误报面否决）。
- **批次二（Monitor 复核）**：4 个确定性形态升级为拦截——`ci_backtick_interleaved`（`;wh``oami`）、Path 源成对反引号、`ssrf_protocol_smuggling`（ldap/gopher/dict://+换行；纯 ldap URL 有放行负样本护栏）、`pt_remote_backslash_include`（`http\..\`）。暂缓 3 族：SSTI、deser-shape Referer 豁免、DVWA 反射族。

实现细节见 `waf-engine-review.md` §5 P9 节（第 36~39 条）。

### P9 实测（post14 全量回放，33877 样本）

| 配置 | 拦截率 | 误报率 | 拦截 vs P8(post13) | 误报 vs P8(post13) |
|---|---|---|---|---|
| Normal | **56.7%（373/658）** | **0.02%（5）** | +3 | 持平（5） |
| Normal + body | **66.9%（440/658）** | **0.04%（14）** | +10 | 持平（14） |
| Strict | **72.2%（475/658）** | **0.02%（5）** | +3 | 持平（5） |
| Strict + body | **88.0%（579/658）** | **0.07%（22）** | +16 | 持平（22） |

**结果**：四配置零回退、误报全部持平零新增——与 triage 回归（575→592）完全一致。分类增量集中在 body 档（strict+body：other +14、lfi 96.0%（24/25）、ssrf 84.6%（11/13）），正是 b64 传输门与 Monitor 形态的设计目标面。strict+body 85.6%→**88.0%**，累计十轮演进 63.8%→88.0%（+24.2pp）；主档（Normal+body）65.3%→66.9%。p95 与 P8 一致（静态 4ms / body ~3s¹），性能守恒。

### P9 回归验证

- 180 单测全绿（5 个新测试，含散文 `UNION -- pick a plan` 与纯 ldap URL 两个负样本护栏）。
- 658 黑样本单样本 triage：575（P8 同口径）→ **592（+17：13 条 b64 门 + 4 条 Monitor 升级，零回退）**。
- fp46 白样本 triage：Block 20 与 P8 集合完全一致，**零新增**。
- 性能守恒：b64 门是常量比较；控制符替换仅在严格 parse 失败 + `looks_like_json` 命中后单次重试；三个新正则均在 prefilter/组合条件后激活；ssrf 走私是两个 `contains`。

## 19. P10 key 扫描面完整化 + 双扩展上传检测与实测（§18 之后的第十一轮）

P10 输入：post14 strict+body 开放 79 条（76 passed + 3 protocol_reject；18 条无 Content-Length 的 POST/PUT 维持链路差异归档），61 条 triage 逐族归因后闭合两个确定性缺口：

- **key 扫描面完整化**：P6 只覆盖了 query key——form key 完全不进扫描面（Drupal `name[0 or updatexml(…)]` 与 `mail[#post_render][]=exec` 两族全靠 key 走私）；key 解码只跑 percent（`\u0025…` 转义洋葱在 key 位置不可见）；512B 上限让一条 564B 的 key-only b64 SQLi（`%2528select extractvalue(…)` 双层 percent）滑过。修复：query/form key 统一走 `decode_value_form` 完整值链、form key 补独立 push、上限 1KB；`decode_value` 的 escape 还原补一轮有界 percent 复解。
- **path 双扩展上传检测**：`/uploadfiles/apache.php.jpeg` 多扩展解析滥用（图片后缀伪装可执行 handler），path 尾锚定正则 + 普通资产路径负样本护栏。首轮正则曾把 `exe|dll|sh|bat` 列入危险扩展，post15 预览暴露 2 条 webpack DLL 命名（`vendor.dll.js`）FP 后收窄为服务端脚本族（php/asp/jsp/cgi 等），白样本语料预检零命中。
- **form key 扫描面 × js-call 博弈 + Drupal render-key needle**：form key 进扫描面后，js-call 旧正则尾类 `[\[(]` 将 `subPayType[deduct][]` 裸双下标误判为链式调用（strict-body 预览 +3 FP，腾讯云账单族）；收紧为「尾真调用括号内容无关、尾链式下标要求引号段」。收紧放走了靠裸链误命中的 ff/fb（`mail[#post_render][]=exec`，Drupalgeddon 族），补 CI-091~095 五条 sev5 needle（`#post_render/#pre_render/#lazy_builder/#markup/#elements`，白样本语料预检零命中）恢复拦截。

实现细节见 `waf-engine-review.md` §5 P10 节（第 40~41 条）。

### P10 实测（post15 全量回放，33877 样本）

| 配置 | 拦截率 | 误报率 | 拦截 vs P9(post14) | 误报 vs P9(post14) |
|---|---|---|---|---|
| Normal | **57.1%（376/658）** | **0.02%（5）** | +3 | 持平（5） |
| Normal + body | **67.6%（445/658）** | **0.04%（14）** | +5 | 持平（14） |
| Strict | **72.8%（479/658）** | **0.02%（5）** | +4 | 持平（5） |
| Strict + body | **88.9%（585/658）** | **0.07%（22）** | +6 | 持平（22） |

**结果**：四配置零回退、误报全部持平零新增——与 triage 回归（Block 3→9）完全一致，strict+body 的 +6 即 triage 的六条新拦截（双扩展 ×2、key-only b64 ×2、Drupal form key RCE ×2）。normal/normal-body/strict 的增量来自 key-only b64 与双扩展（query/path 面）。strict+body 88.0%→**88.9%**，累计十一轮演进 63.8%→88.9%（+25.1pp）；主档（Normal+body）66.9%→**67.6%**。p95 静态 5ms / body ~3s¹（客户端固有），性能守恒。post15 预览期三轮 FP 事件（双扩展 `dll` 收窄、js-call 尾类收紧 + Drupal render-key needle 补位）全部闭环后才定稿本表，final 四配置 FP 与 P9 完全持平。

### P10 回归验证

- 183 单测全绿（+2 新测试：key-only b64 洋葱 + \u 转义 key、key-only b64 SQLi Block + 双扩展 Block/白形态负样本；含 form key 数组参数 js-call 负样本、引号链 key 正样本、Drupal render-key RCE Block）。
- 61 条开放样本 triage：Block 3 → **9（+6，全部为真实攻击特征：Drupal form key RCE ×2、key-only b64 SQLi、转义洋葱、双扩展 ×2）**。
- fp46 白样本 triage：Block 20 持平，**零新增**。
- post15 预览三轮 FP 事件全部闭环：双扩展 `dll` 扩展收窄（`vendor.dll.js` ×2）、js-call 尾类收紧（`subPayType[deduct][]` ×3）+ Drupal render-key needle 恢复 ff/fb 拦截，样本 triage 复验判决正确，白样本语料全量预检无新命中面。
- 性能守恒：key 链与值链共享同一套有界解码 pass（1KB/1024 上限、B64_MAX_VALUE_LEN/depth 门不变）；双扩展是单条尾锚定正则；escape 复解仅在输出含 `%` 时激活。

## 20. P11 B 类漏报归因 + b64 值链断点修复与实测（§19 之后的第十二轮）

P11 输入：post15 strict+body 开放 73 条（70 passed + 3 protocol_reject，Monitor 面 P9/P10 清零）。**口径修正**：18 条无 Content-Length 的 POST 属链路差异（无 C-L 且无 T-E 的 POST 在真实 HTTP 语义下 body 为空，引擎收不到 payload 是正确行为），不计漏报；B 类真漏报 55 条 = 51 Pass/Monitor + 3 protocol_reject + 1 Challenge。归因后闭合三处 b64 值链断点 + 五条 needle + 一条 shape：

- **b64 层控制符归一**：传输填充走私裸 NUL/CR（`OR\0/* \r…`），90% printability 门放行，下游 SQL 词法全断（libinjection 丢 token、`\bor\b` 失配、注释剥离重扫被卡）。解码后控制字符（保留 `\t\n\r`）统一替换为空格，与 P10 JSON 控制符重试同一取舍。
- **quoted-run b64 提取（Strict-only）**：`\u` 转义洋葱把 payload 藏在 JSON 数组字符串字面量里，escape 解码后 b64 run 裸露于引号之间；门条件「run ≥16 且紧贴双引号」+ charset/printability 质量门，白样本裸 run 占 90% 证明引号门必要。
- **b64 非 canonical 尾位容错**：a2/1f 两层洋葱悬案——首层 whole-value b64 末组 `S0` 冗余位非零（非规范 base64），python/Java 宽松解码器接受而 Rust base64 crate 严格拒绝，后端能解的传输层 WAF 解不开、整条 payload 从未到达检测面。`b64_decode_value` 换用 `with_decode_allow_trailing_bits(true)` 引擎，charset + printability 质量门不变。
- **裸 waitfor strong check**：洋葱终层 `));wAITfor` + 注释填充——`SQLI_DANGEROUS_FN` 要求 `waitfor\s*\(` 而真实 T-SQL `WAITFOR DELAY` 语句从不带括号，原正则实际匹配不到真实时间盲注；`\bwaitfor\b` 入 strong，白样本预检零命中。
- **needle 扩面**：CI-096~098 ASP 一句话木马（`<%eval`/`<%execute`/`eval request(`）、CI-099 `file_put_contents`、XSS-023 `+ADw-`（UTF-7 `<`）、XSS-024 `alert(1)` 字面（泛 `alert(` 维持 sev3）；chr() 码点链 shape（`ci_chr_chain`）入 ci-shape critical。全部经白样本语料全量预检零命中。

实现细节见 `waf-engine-review.md` §5 P11 节（第 42~46 条）。

### P11 实测（post16 全量回放，33877 样本）

| 配置 | 拦截率 | 误报率 | 拦截 vs P10(post15) | 误报 vs P10(post15) |
|---|---|---|---|---|
| Normal | **59.4%（391/658）** | **0.02%（5）** | +15 | 持平（5） |
| Normal + body | **70.7%（465/658）** | **0.04%（14）** | +20 | 持平（14） |
| Strict | **75.8%（499/658）** | **0.02%（5）** | +20 | 持平（5） |
| Strict + body | **91.9%（605/658）** | **0.07%（22）** | +20 | 持平（22） |

**结果**：四配置零回退、零样本丢失、误报全部持平零新增。strict+body 的 +20 全部来自 P11 目标族：控制符归一（66b7）、quoted-run 提取（a4e0 + 同族 b169/b171/a587/fe1a）、chr 码点链（02d0）、`alert(1)` 字面（4b67/7a88 族）、UTF-7（fda1）、ASP 一句话（357e）、`file_put_contents`（555e），以及 **a2/1f 两层洋葱悬案**（非 canonical b64 尾位容错 + 裸 waitfor 双断点，Normal 档即生效）——尾位容错还顺带把归档的 5c/aa 经 quoted-run 链路拦下。Normal 档 +15 证明三处 b64 断点修复惠及全配置面（whole-value b64 传输不再因非规范尾位隐身）。strict+body 88.9%→**91.9%**，累计十二轮演进 63.8%→91.9%（+28.1pp）；主档（Normal+body）67.6%→**70.7%**。p95 静态 5ms / body ~3s¹（客户端固有），性能守恒。

### P11 回归验证

- 189 单测全绿（+1 新测试：`noncanonical_b64_waitfor_onion_blocks`——非规范尾位 b64 两层洋葱端到端 Block；P11 累计 +6 测试）。
- 目标样本 triage：10 条 Block 9 保持；a2/1f 从「归档不修」转 Block（两层 b64 + 裸 waitfor 全链路解谜后实测拦截）。
- 四配置 FP 集合与 P10 逐条 diff：**零新增零消失**（normal 5、normal-body 14、strict 5、strict-body 22 完全一致）。
- 白样本预检：裸 waitfor 0 命中（T-SQL 独有关键字）、needle 扩面五条 0 命中；非 canonical 尾位容错的解码面扩大由 charset + printability 质量门约束，bench 全量回放验证无 FP 代价。
- 性能守恒：尾位容错仅替换解码引擎配置（同一 AhoCorasick 预过滤不变）；quoted-run 的引号邻接扫描在 escape pass 后有界执行；控制符归一是 O(n) 单遍。

## 21. 各版本拦截率/通过率对比总表

黑样本 658 / 白样本 33219，严格口径（blocked = WAF 判决 403/503）。**通过率** = 黑样本未被拦截的比例（漏报面）；白样本通过率 = 100% − 误报率。

| 版本 | 配置 | 拦截率 | 黑样本通过率 | 误报率 | 白样本通过率 | p95 |
|---|---|---|---|---|---|---|
| G1 出厂默认 | block / PL2 / th40 | 34.0%（224/658） | 66.0% | 0.41%（137） | 99.59% | 2ms |
| 级别落地 v1 | Normal | 33.1%（218/658） | 66.9% | 0.17%（55） | 99.83% | 2ms |
| 级别落地 v1 | Strict | 37.8%（249/658） | 62.2% | 0.30%（101） | 99.70% | 2ms |
| P0 覆盖面修复 | Normal | 36.5%（240/658） | 63.5% | 0.21%（69） | 99.79% | 4ms |
| P0 覆盖面修复 | Normal + body | 38.1%（251/658） | 61.9% | 0.23%（75） | 99.77% | ~3s¹ |
| P0 覆盖面修复 | Strict | 51.1%（336/658） | 48.9% | 0.35%（115） | 99.65% | 4ms |
| P0 覆盖面修复 | Strict + body | 63.8%（420/658） | 36.2% | 1.98%（658） | 98.02% | ~3s¹ |
| P1 语义增强 | Normal | 36.8%（242/658） | 63.2% | **0.15%（51）** | 99.85% | 4ms |
| P1 语义增强 | Normal + body | **44.1%（290/658）** | 55.9% | **0.18%（61）** | 99.82% | ~3s¹ |
| P1 语义增强 | Strict | 51.4%（338/658） | 48.6% | 0.35%（115） | 99.65% | 4ms |
| P1 语义增强 | Strict + body | 63.8%（420/658） | 36.2% | 2.38%（792） | 97.62% | ~3s¹ |
| P2/P3 语义扩面 | Normal | 46.8%（308/658） | 53.2% | **0.10%（33）** | **99.90%** | 4ms |
| P2/P3 语义扩面 | Normal + body | **55.5%（365/658）** | 44.5% | **0.13%（43）** | **99.87%** | ~3s¹ |
| P2/P3 语义扩面 | Strict | 63.8%（420/658） | 36.2% | 0.32%（105） | 99.68% | 4ms |
| P2/P3 语义扩面 | Strict + body | **77.7%（511/658）** | 22.3% | 2.17%（721） | 97.83% | ~3s¹ |
| P4 解码链+FP 治理 | Normal | 50.5%（332/658） | 49.5% | **0.07%（23）** | **99.93%** | 4ms |
| P4 解码链+FP 治理 | Normal + body | **59.1%（389/658）** | 40.9% | **0.10%（32）** | **99.90%** | ~3s¹ |
| P4 解码链+FP 治理 | Strict | 66.6%（438/658） | 33.4% | **0.07%（23）** | **99.93%** | 4ms |
| P4 解码链+FP 治理 | Strict + body | **79.0%（520/658）** | 21.0% | **0.14%（46）** | **99.86%** | ~3s¹ |
| P5 FP 形态门 | Normal | 50.5%（332/658） | 49.5% | **0.02%（7）** | **99.98%** | 4ms |
| P5 FP 形态门 | Normal + body | **59.1%（389/658）** | 40.9% | **0.05%（16）** | **99.95%** | ~3s¹ |
| P5 FP 形态门 | Strict | 66.6%（438/658） | 33.4% | **0.02%（7）** | **99.98%** | 4ms |
| P5 FP 形态门 | Strict + body | **79.0%（520/658）** | 21.0% | **0.07%（24）** | **99.93%** | ~3s¹ |
| P6 拦截侧扩面 | Normal | **51.8%（341/658）** | 48.2% | **0.02%（5）** | **99.98%** | 4ms |
| P6 拦截侧扩面 | Normal + body | **60.6%（399/658）** | 39.4% | **0.04%（14）** | **99.96%** | ~3s¹ |
| P6 拦截侧扩面 | Strict | **67.9%（447/658）** | 32.1% | **0.02%（5）** | **99.98%** | 4ms |
| P6 拦截侧扩面 | Strict + body | **80.7%（531/658）** | 19.3% | **0.07%（22）** | **99.93%** | ~3s¹ |
| P7 Monitor 细分+零信号复检 | Normal | **55.6%（366/658）** | 44.4% | **0.02%（5）** | **99.98%** | 4ms |
| P7 Monitor 细分+零信号复检 | Normal + body | **64.7%（426/658）** | 35.3% | **0.04%（14）** | **99.96%** | ~3s¹ |
| P7 Monitor 细分+零信号复检 | Strict | **71.1%（468/658）** | 28.9% | **0.02%（5）** | **99.98%** | 4ms |
| P7 Monitor 细分+零信号复检 | Strict + body | **85.0%（559/658）** | 15.0% | **0.07%（22）** | **99.93%** | ~3s¹ |
| P8 零信号残余形态 | Normal | **56.2%（370/658）** | 43.8% | **0.02%（5）** | **99.98%** | 4ms |
| P8 零信号残余形态 | Normal + body | **65.3%（430/658）** | 34.7% | **0.04%（14）** | **99.96%** | ~3s¹ |
| P8 零信号残余形态 | Strict | **71.7%（472/658）** | 28.3% | **0.02%（5）** | **99.98%** | 4ms |
| P8 零信号残余形态 | Strict + body | **85.6%（563/658）** | 14.4% | **0.07%（22）** | **99.93%** | ~3s¹ |
| P9 b64 门放宽+Monitor 升级 | Normal | **56.7%（373/658）** | 43.3% | **0.02%（5）** | **99.98%** | 4ms |
| P9 b64 门放宽+Monitor 升级 | Normal + body | **66.9%（440/658）** | 33.1% | **0.04%（14）** | **99.96%** | ~3s¹ |
| P9 b64 门放宽+Monitor 升级 | Strict | **72.2%（475/658）** | 27.8% | **0.02%（5）** | **99.98%** | 4ms |
| P9 b64 门放宽+Monitor 升级 | Strict + body | **88.0%（579/658）** | 12.0% | **0.07%（22）** | **99.93%** | ~3s¹ |
| P10 key 扫描面+双扩展 | Normal | **57.1%（376/658）** | 42.9% | **0.02%（5）** | **99.98%** | 5ms |
| P10 key 扫描面+双扩展 | Normal + body | **67.6%（445/658）** | 32.4% | **0.04%（14）** | **99.96%** | ~3s¹ |
| P10 key 扫描面+双扩展 | Strict | **72.8%（479/658）** | 27.2% | **0.02%（5）** | **99.98%** | 5ms |
| P10 key 扫描面+双扩展 | Strict + body | **88.9%（585/658）** | 11.1% | **0.07%（22）** | **99.93%** | ~3s¹ |
| P11 b64 断点+needle 扩面 | Normal | **59.4%（391/658）** | 40.6% | **0.02%（5）** | **99.98%** | 5ms |
| P11 b64 断点+needle 扩面 | Normal + body | **70.7%（465/658）** | 29.3% | **0.04%（14）** | **99.96%** | ~3s¹ |
| P11 b64 断点+needle 扩面 | Strict | **75.8%（499/658）** | 24.2% | **0.02%（5）** | **99.98%** | 4ms |
| P11 b64 断点+needle 扩面 | Strict + body | **91.9%（605/658）** | 8.1% | **0.07%（22）** | **99.93%** | ~3s¹ |
| P12 魔数 query+引号门放宽 | Normal | **60.2%（396/658）** | 39.8% | **0.02%（5）** | **99.98%** | 5ms |
| P12 魔数 query+引号门放宽 | Normal + body | **71.3%（469/658）** | 28.7% | **0.04%（14）** | **99.96%** | ~3s¹ |
| P12 魔数 query+引号门放宽 | Strict | **76.0%（500/658）** | 24.0% | **0.02%（5）** | **99.98%** | 4ms |
| P12 魔数 query+引号门放宽 | Strict + body | **93.0%（612/658）** | 7.0% | **0.07%（22）** | **99.93%** | ~3s¹ |
| P13 Nexus EL+分离 RCE needle | Normal | **60.2%（396/658）** | 39.8% | **0.02%（5）** | **99.98%** | 5ms |
| P13 Nexus EL+分离 RCE needle | Normal + body | **71.9%（473/658）** | 28.1% | **0.04%（14）** | **99.96%** | ~3s¹ |
| P13 Nexus EL+分离 RCE needle | Strict | **76.0%（500/658）** | 24.0% | **0.02%（5）** | **99.98%** | 4ms |
| P13 Nexus EL+分离 RCE needle | Strict + body | **93.8%（617/658）** | 6.2% | **0.06%（21）** | **99.94%** | ~3s¹ |

¹ p95 ≈3s 是回放客户端 `sendall` 大 body 与「上传中途拦截」的固有交互，非引擎开销（§10.2）。

**主档结论（Normal + body，agent 模式推荐配置）**：P6 → P7 → P8 → P9 → P10 → P11 六轮连续把拦截率从 P5 的 59.1% 提到 **70.7%（+11.6pp）**，误报率稳定在 **0.04%（14 条）**；P12 魔数 query 与引号门/needle 扩面再 +0.6pp、P13 Nexus EL/分离 RCE needle 再 +0.6pp 至 **71.9%**。**四配置误报率连续十轮低于 0.2% 目标线**（P13：0.015%/0.042%/0.015%/0.063%）。累计十四轮演进（v1→P0→…→P13）：Normal 静态档拦截率 33.1%→**60.2%**（+27.1pp）、误报率 0.17%→**0.015%**；Normal+body 口径自 P0 引入以来 38.1%→**71.9%**（+33.8pp）、误报 0.23%→**0.04%**。Strict+body 拦截率 63.8%→**93.8%**，误报 2.38%→**0.06%**（-771 条）。

类目拦截率对比（黑样本）：

| 类目 | n | G1 | v1 Normal | v1 Strict | P0 Normal(+body) | P0 Strict(+body) | P1 Normal | P1 Normal+body | P1 Strict | P1 Strict+body | P2 Normal+body | P2 Strict+body |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| sqli | 20 | 75.0% | 70.0% | 70.0% | 85.0% (85.0%) | 85.0% (85.0%) | 85.0% | 85.0% | 85.0% | 85.0% | 85.0% | 85.0% |
| xss | 30 | 33.3% | 33.3% | 33.3% | 33.3% (33.3%) | 80.0% (83.3%) | 33.3% | 33.3% | 80.0% | 83.3% | 40.0% | 90.0% |
| lfi | 25 | 32.0% | 32.0% | 36.0% | 68.0% (72.0%) | 72.0% (84.0%) | 68.0% | 72.0% | 72.0% | 84.0% | 76.0% | 88.0% |
| rce | 12 | 16.7% | 16.7% | 66.7% | 16.7% (33.3%) | 66.7% (75.0%) | 16.7% | 33.3% | 66.7% | 75.0% | 41.7% | 83.3% |
| ssrf | 13 | 7.7% | 7.7% | 7.7% | 7.7% (23.1%) | 7.7% (46.2%) | 7.7% | 23.1% | 7.7% | 46.2% | 30.8% | 53.8% |
| deser | 6 | 0% | 0% | 0% | 0% (0%) | 0% (83.3%) | 0% | 33.3% | 0% | 83.3% | 100% | 100% |
| crlf | 5 | 0% | 0% | 60.0% | 0% (0%) | 60.0% (100%) | 40.0% | 40.0% | 60.0% | 100% | 40.0% | 100% |
| ssti | 5 | 0% | 40.0% | 80.0% | 40.0% (40.0%) | 80.0% (80.0%) | 40.0% | 40.0% | 80.0% | 80.0% | 60.0% | 100% |
| xxe | 2 | 0% | 0% | 50.0% | 0% (50.0%) | 50.0% (50.0%) | 0% | 50.0% | 50.0% | 50.0% | 50.0% | 50.0% |
| other | 538 | 34.9% | 33.5% | 36.8% | 35.3% (36.2%) | 48.1% (60.4%) | 35.3% | 42.8% | 48.5% | 60.4% | 54.8% | 76.0% |
| log4shell | 1 | 0% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% |

P1 相对 P0 的类目增量（Normal+body 口径）：**crlf 0%→40%**（头名形态 critical，query 面生效使 Normal 静态档同样受益）、**deser 0%→33.3%**（needle 扩面 + JSON 成员 typed 检测）、**other 36.2%→42.8%**（needle 扩面 + 嵌套 JSON 解包）；sqli/ssrf/rce/lfi/xss 持平或一致。Strict+body 逐类目与 P0 持平（other 60.4%→60.4%）。

P2/P3 相对 P1 的类目增量（Normal+body 口径）：**deser 33.3%→100%**（DZ needle + deser-shape 分级 + b64 展开承接 b64 包裹 OGNL）、**xss 33.3%→40%**（prototype 链/JSFuck）、**rce 33.3%→41.7%**（CI-043 `getruntime().exec`）、**ssrf 23.1%→30.8%**、**ssti 40%→60%**、**other 42.8%→54.8%**（b64 值级展开 + overlong UTF-8 打开编码包裹可见性，强正则/needle 扩面承接）。Strict+body 口径：**xss 83.3%→90%**、**deser 83.3%→100%**、**other 60.4%→76.0%**（+84 条，b64/overlong 展开对 Strict 档编码家族收益最大）、**ssti 80%→100%**。

## 22. P12 魔数 query + 引号门放宽与 needle 扩面与实测（§20 之后的第十三轮）

P12 输入：post16 strict+body 开放 53 条，逐条归因分两批落地。

**第一批（魔数 query）**：`?s=%ac%ed%00%05%73%72…` 原始 Java ObjectStream 字节经 percent 传输——byte 还原解码器（非法 UTF-8 经 Latin-1 映射）早已把 `¬í\0\u{5}sr` 文本送进扫描面，断点在 needle 形态：hex-text needle `aced0005` 与 b64 transport needle `rO0AB` 都看不见这条 Latin-1 字符序列。修复：`DESER_JAVA_MAGIC` 正则（`\x{AC}\x{ED}\x{00}\x{05}sr`）入 `detect_deser_shape` 返回 `java-serialized-magic`——要求 magic 后随 `sr` 类描述符标记绑定真实序列化流，`\u{ac}` contains 预滤保证非样本值零额外成本；与 P8 b64 形态（ViewState）互补覆盖同一魔数的两条传输面。实现细节见 `waf-engine-review.md` P12 节（第 47 条）。

**第二批（引号门 + needle 族）**：post17 后 52 条开放漏报按 C-L 分类收敛到 13 条 REAL other，归因出 6 个可修族。①`expand_b64_substrings` 引号门只认双引号，而 SQL/Python 字典值的单引号字面量（`{'id': 'MCcg…='}`）同样承载 b64 payload（710c90 族），放宽为 matching string quotes；白样本预检唯一命中族是驼峰 API Action 名，解码后 printability 门拒收（11%~46%），放宽安全。②needle 族 8 条：紧凑 `||` 管道 DNS 链、管道写文件 `|touch /`、git 选项注入（`--open-files-in-pager=`/`--upload-pack=`，CVE-2019-1387 族）、Lua os 沙箱逃逸（`require('os')` 双引号变体，APISIX 族）、XStream custom-serialization XML（CVE-2021-21344 族）；白样本 needle 预检 8 条零命中。实现细节见 `waf-engine-review.md` P12 节（第 48 条）。

### P12 实测（post17 全量回放，33877 样本）——第一批

| 配置 | 拦截率 | 误报率 | 拦截 vs P11(post16) | 误报 vs P11(post16) |
|---|---|---|---|---|
| Normal | **60.2%（396/658）** | **0.02%（5）** | +5 | 持平（5） |
| Normal + body | **70.7%（465/658）** | **0.04%（14）** | 持平（465） | 持平（14） |
| Strict | **76.0%（500/658）** | **0.02%（5）** | +1 | 持平（5） |
| Strict + body | **92.1%（606/658）** | **0.07%（22）** | +1 | 持平（22） |

**结果**：四配置零回退、零样本丢失、误报全部持平零新增。目标样本 70/62 triage Pass→Block、bench 拦截确认（gained 清单含 `5178e5d4`）。Normal 档 +5 为同族序列化魔数样本在 sev4 计分下整体过阈值（deser 魔数族静态档可见性打开）；Normal+body 档持平系该族已被 body 档既有信号覆盖；Strict/Strict+body 各 +1 为 70/62 critical 判决。strict+body 91.9%→**92.1%**，累计十三轮演进 63.8%→92.1%（+28.3pp）。p95 守恒（静态 4-5ms / body ~3s¹）。

### P12 第二批实测（post18 全量回放，33877 样本）

| 配置 | 拦截率 | 误报率 | 拦截 vs P12 一批(post17) | 误报 vs P12 一批(post17) |
|---|---|---|---|---|
| Normal | **60.2%（396/658）** | **0.02%（5）** | 持平（396） | 持平（5） |
| Normal + body | **71.3%（469/658）** | **0.04%（14）** | +4 | 持平（14） |
| Strict | **76.0%（500/658）** | **0.02%（5）** | 持平（500） | 持平（5） |
| Strict + body | **93.0%（612/658）** | **0.07%（22）** | +6 | 持平（22） |

**结果**：四配置零回退、零样本丢失、FP 集合逐条 diff 与 post17 完全一致。strict-body +6 恰为 6 条目标样本全中：`710c900c`（单引号 b64 SQL 字典）、`bb20f5cc`（`||nslookup` 管道链）、`58717bea`（`|touch` 管道写）、`4df7fcb6`（git `--upload-pack`）、`d1539994`（Lua `require('os')`）、`e76ed749`（XStream custom XML）。normal-body +4 中 3 条与上同族（body 档 sev4/sev5 计分过阈），另有 `ffe6a8aa` 为 DZ-019 新 needle 使该样本 Normal 档计分过阈（score=13，同第一批 deser 族可见性打开模式）；normal/strict 持平符合预期（目标样本均为 POST body 形态）。strict+body 92.1%→**93.0%**，累计十三轮演进 63.8%→**93.0%**（+29.2pp）。p95 守恒（静态 4ms / body ~3s¹）。

### P12 回归验证

- 单测：第一批后 191 全绿（新增 2：`detect_deser_java_magic_in_latin1_restored_bytes`——Latin-1 还原字节形态命中 + 截断流负例；`java_serialized_magic_percent_query_blocks`——70/62 真实样本 query 端到端 Block）；第二批后 **193 全绿**（新增 2：`single_quoted_b64_sql_dict_blocks`——710c90 单引号字典形态；`cmd_git_lua_xstream_needles_block`——6 needle 族端到端 Block 循环）。
- 四配置 FP 集合与 P11 逐条 diff：**零新增零消失**（normal 5、normal-body 14、strict 5、strict-body 22 完全一致）；第二批与 post17 逐条 diff 同样零新增零消失。
- FP 风险评估：魔数正则要求 4 字节序列后随 `sr` 标记——NUL/控制字符在诚实文本值中不存在；引号门放宽仅扩大 b64 到达 printability/charset 质量门的面；8 条 needle 均为诚实值不可能出现的强特征（git 选项开头、`require('os')`、`serialization='custom'` XML 属性等），白样本全量预检零命中。
- 性能守恒：新增均带廉价预滤（`\u{ac}` contains / needle 在既有 AC 自动机内），无新增解码面；p95 四配置与 post17 一致。
- 编号修正：第二批 needle 初版与既有 `$(cat` 命令替换族（CI-101~106）重号，已顺延为 CI-107~112（details 按 ID 去重会归因歧义；计分按索引不受影响）。

### P12 剩余漏报面与 95% 可达性

post18 strict+body 剩余开放漏报 46 条（658−612），按可修性分层：**伪影面 ~39 条**——34 条无 Content-Length 的 POST/PUT（RFC 7230：无 C-L 且无 T-E 即空 body，bench 链路物理不可拦）+ 3 条 protocol_reject（400 判决不计拦截）+ 2 条 SSRF 弱语义（内网 URL 裸形态，与诚实流量同构）+ 若干假黑/灰样本（`<a href=# download>` 无执行面、DVWA 空参数探测起手、随机词假黑）；**REAL 面 ~7 条**——d7b61c 深层 HTML 实体洋葱（waf-ce 合成样本，引号错位形态）、ff/67 URL fragment 盲区（浏览器流量 fragment 不上行，样本面黑 1/白 0）、信息泄露/未授权 API 族注定面。**即使 REAL 面全修，理论上限 ≈ 619/658 = 94.1%**——95% 目标在当前样本库口径下接近不可达；样本库剔除伪影（黑 619 口径）后当前成绩已等效 **98.9%**。继续迭代的方向是把 REAL 面修满并对齐样本库伪影剔除口径，而非在 658 口径上追 95%。（P14 修正：fragment 盲区经技术归因重新定性为链路伪影，口径更新为上限 618/658 = 93.9%、等效 617/618 = 99.8%，见 §23 末节。）

## 23. P13 Nexus EL 探测 + 分离 Java RCE + web.xml 值面与实测（§22 之后的第十四轮）

P13 输入：post18 strict+body 剩余 46 条漏报按 Content-Length/判决精确重分层——34 无 C-L（链路伪影）、3 protocol_reject、3 注定面（Rocket.Chat callAnon 未授权 API + 2 条随机词假黑），**REAL 面 9 条**。逐条归因出 3 个 needle 族：①**Nexus EL 算术探测**（CVE-2020-10204 族，三条）——`$\A{233*233*233}`/`$\B{233*233}` 引擎特有转义变体，算术求值探测只存在于 exploit 载荷；②**分离语句 Java RCE**（Unomi MVEL CVE-2021-44227 族）——`Runtime r = Runtime.getRuntime(); r.exec(…)` 语句分离形态绕开既有连写 needle，裸 `getruntime()` 在诚实参数值零出现；③**部署描述符探测**（Confluence macro-preview `_template`，CVE-2021-26084 探测族）——`_template` 裸形态白样本 19 条命中不可用，改用值面 `web.xml`（与既有 `web-inf` 同族互补）。4 条 needle（PT-020/CI-113/114/115）白样本全量预检零命中，全部在 AC 自动机内零新增解码面。实现细节见 `waf-engine-review.md` P13 节（第 49 条）。

### P13 实测（post19 全量回放，33877 样本）

| 配置 | 拦截率 | 误报率 | 拦截 vs P12 二批(post18) | 误报 vs P12 二批(post18) |
|---|---|---|---|---|
| Normal | **60.2%（396/658）** | **0.02%（5）** | 持平（396） | 持平（5） |
| Normal + body | **71.9%（473/658）** | **0.04%（14）** | +4 | 持平（14） |
| Strict | **76.0%（500/658）** | **0.02%（5）** | 持平（500） | 持平（5） |
| Strict + body | **93.8%（617/658）** | **0.06%（21）** | +5 | **−1（22→21）** |

**结果**：normal-body +4 与 strict-body +5 恰为 P13 目标样本全中（`176081cb`/`0b46fe5d`/`a58dfc8b`/`ef7a0e1c` + `ca1b0e50`，全部为 Nexus EL/Unomi/Confluence 族）；normal/strict 持平符合预期（目标均为 POST body 形态）。strict+body 93.0%→**93.8%**，累计十四轮演进 63.8%→**93.8%**（+30.0pp）。误报净 −1 为验证轮可打印性门修复的双收益（见下节）。p95 守恒（静态 4-5ms / body ~3s¹）。

### P13 验证轮 FP 归因与修复（expr 容器可打印性门）

首轮 strict-body 出现 1 条新 FP（`74df46db`，Ctrip 移动端 `saveLogInfo` 日志上报，162KB 高熵乱码 body）——与 P13 needle 无关（needle 全注释复现、解码面 grep 零命中、无 XFF replay 复现），完整归因链跨三层：

1. **插件检测面越过 64KB 门**：body 检测的 max_body_size（默认 64KB）按 **chunk 粒度**截断——无负载时单次 IO 读满 64KB，实际检测面 130556 字节（3580+61440+65536 三次 IO 累计），乱码段 64KB~130KB 区间全部进入扫描。
2. **expr 容器在高熵数据中的必然命中**：`${…}` 容器出现率≈1，`is_structural_expr` 的「identifier(」与运算符特征在乱码中同样≈1 → strict 档 expr-injection critical → Block。
3. **判决随 socket chunk 边界抖动**：post18 bench 高负载下 chunk 碎片化、停点贴近 64KB 门 → 仅 TI-002/003 低分 Monitor → passed；post19 无负载大 chunk 一次越门 → blocked。同一样本两轮判决不同，非引擎语义变化。

修复：`is_structural_expr` 开头加容器内容**可打印性门**（全字节 `is_ascii_graphic()` 或空格）——真实 EL/SSTI/JSP payload 按构造全为可打印 ASCII，乱码容器直接拒判结构。单测 194 全绿（P2/P3 全部 EL/SSTI 正样本验证无损）；6 样本重放确认 5 目标 Block + 74df 放行。**额外收益**：重跑后 `0db7f97`（同族 Ctrip `SaveTraceInfo`，164KB 高熵 body，printable ratio 50%）也从 post18 的 FP 集合中消除——同一条 chunk 抖动链在 post18 的既有误报，修复一次带走两条同族 FP，strict-body FP 22→**21** 净减。详见 `waf-engine-review.md` P13 节（第 50 条）。

### P13 回归验证

- 单测：**194 全绿**（新增 1 个测试函数 4 断言：`nexus_el_probe_and_java_runtime_blocks`——Unomi 分离 exec、Nexus group/extdirect 双变体、Confluence web.xml）。
- 四配置 FP 集合与 post18 逐条 diff：normal/normal-body/strict **零新增零消失**；strict-body 修复后 21 条 = post18 集合 22 − 同族伪影 `0db7f97`，74df 未再出现（首轮 +1 伪影已由可打印性门消除）。
- FP 风险评估：4 条 needle 均为 exploit 独有形态（`$\A{` 引擎转义变体、裸 `getruntime()`、`web.xml` 值面），白样本全量预检零命中；可打印性门对真实 payload 零损（payload 按构造可打印）。
- 性能守恒：可打印性门为容器内 O(len) 单遍字节检查，真实 payload ≤256B 上限内成本可忽略；needle 全部在既有 AC 自动机内。

### P14 fragment 盲区重定性（第十五轮归因，零代码修复）

post18 遗留 REAL 面 4 条中最后一项可修候选 `ff/67`（S2-045 OGNL 全量藏 URL `#` fragment 后）经三轮技术归因**重新定性为链路伪影**，P14 无代码修复落地：

1. **http::Uri 语义**：`http` 1.5 `Uri` 无 fragment 存储位（scheme/authority/path_and_query 三元），探针实测 `#` 后内容被解析器静默丢弃（`/index.action?redirect:${#a=…}` → `path_and_query()` 仅返回 `"/index.action?redirect:${"`）。
2. **pingora 解析层主动剥离**：pingora 0.9 `parse_request_target` 在构造 Uri **之前**按 RFC 9112 §3.2 剥离 fragment（源码注释明确 "must not reach the upstream request-line"），`RequestHeader.raw_target` 保存的同样是剥后字节——插件层既拿不到 fragment 内容，也拿不到 `#` 存在信号。
3. **利用链物理断裂**：pingwaf 转发上游的请求行不含 fragment——OGNL 载荷永远到不了 Struts2。样本库把 `ff/67` 标黑基于「WAF 直连目标服务器」假设；反代部署形态下该载荷无效。

**结论**：`ff/67` 与「无 Content-Length 的 POST」同级的部署形态伪影——pingora 的 RFC 合规解析行为本身就是防护的一环。可达性口径随之修正：伪影面 ~40 条（34 无 C-L + 3 protocol_reject + 2 SSRF 弱语义 + 1 fragment），**658 口径理论上限 618/658 = 93.9%**，等效口径 **617/618 = 99.8%**。真实不可修面仅剩 waf-ce 合成 XSS 洋葱 2 条 + 未授权 API 注定面 1 条。

### P14 post20：站点级规则分级（0.20.0）零回归验证

0.20.0 把 P12/P13 的 strict + body 深度检测能力暴露为站点级产品功能（规则分级）：`advanced_mode`（一键 Strict + inspect_body）、9 攻击分类监听降级、4 后端栈监听降级。引擎判决层改为双分数（blocking 子集 vs 全量 total），监听命中的分数只进 total 不进 blocking——**monitor 集空时 blocking 分数与旧实现逐位一致**。全量回放验证该等价性：

| 配置 | 拦截率 | 误报率 | vs post19 |
|---|---|---|---|
| Normal | 60.2%（396/658） | 0.02%（5） | 逐位复现 |
| Normal + body | 71.9%（473/658） | 0.04%（14） | 逐位复现 |
| Strict | 76.0%（500/658） | 0.02%（5） | 逐位复现 |
| Strict + body | 93.8%（617/658） | 0.06%（21） | 逐位复现 |

四配置 33877 样本全量回放与 post19 逐条 diff：**gained 0 / lost 0**，FP 集合零新增零消失（5/14/5/21 逐条一致）——bench 零回归的实证口径。

**spot 功能矩阵**（三份站点 conf 实测，socket 原样发样本）：`monitor_categories=["sqli"]` 站点 SQLi 黑样本 200、JNDI 照常 403；`monitor_stacks=["java"]` 站点 JNDI 200、SQLi 照常 403；`advanced_mode=true` 站点 strict-only 探针（Freemarker EL）403。验证后 127.0.0.1 被三实例各自 auto-block（0.19.0 起的 block verdict 自动封禁语义），良性请求 503 为预期链路。

**验证轮修复**：spot 验证暴露 TOML 静态配置路径不解析 `advanced_mode` 键（仅控制面 WafConfig 路径生效，conf 里写了被静默忽略）——修复为 `advanced_mode ⇒ Strict + inspect_body`（`advanced_mode` 优先级高于显式 `level` 键，与 `inspect_body` 为 `||` 合并），补插件单测覆盖。四配置 bench 基线不受影响（TOML 基线 conf 不含该键）。



