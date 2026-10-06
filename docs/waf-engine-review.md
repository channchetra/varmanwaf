# PingWAF 引擎复盘与语义检测演进方案

- 复盘日期：2026-10-04
- 对象：`pingwaf-waf` 引擎全部源码（5839 行）+ 基准实测数据（blazehttp 33877 样本，Normal/Strict 两档）
- 方法：源码通读 + 漏报/误报样本逐条归因 + 关键假设 curl 实测复现 + 业界方案对标
- 基线：Normal 拦截 33.1% / 误报 0.17%；Strict 37.8% / 0.30%（见 `waf-benchmark-report.md` §9）

## 1. 引擎现状全景

### 1.1 检测流水线

```
RequestData
  │ normalize_request          借用式规范化：percent 多层解码(≤3)→HTML 实体→路径折叠；
  │ (Strict 另开 \xHH\uHHHH)   产出 decoded_values（path/query k-v/headers/cookies/body blob）
  ▼
Stage 1（每个解码值）───────────────────────────────
  │ Aho-Corasick 113 needles（LeftmostLongest、case-insensitive、栈过滤）
  │   → SignatureHit{u32 索引+Copy}，按 pattern 去重，sev→评分+critical 判定
  │ libinjection 算法（自研移植）：SQL 词法指纹 + 7 条强正则 / XSS 7 条正则
  │   → strong 命中即 sev5 critical
  │ (Strict) detect_expr_injection：${}/{{ }}/{% %}/<%= %> 容器内结构特征
  ▼
fast-path：critical_hit → 立即 Block（不进规则引擎）
  ▼
Stage 2：14 条托管规则（Cloudflare 风格 DSL）
  │   子评分门 1002/1003（≥60）·聚合 1004（≥80）·Strict 收紧至 50/70 + 1061(rce≥40)
  │   allow 预短路 → Block/Challenge/Log
  ▼
评分合成：total≥threshold(40) Block；>0 Monitor；否则 Pass
（Pass 零字符串构建；其余延迟格式化）
```

### 1.2 性能画像

| 阶段 | 算法 | 复杂度 | 实测 |
|---|---|---|---|
| 规范化 | 线性扫描 + `+`/`%`/`&` 检测门 | O(n)，几乎零分配（method Cow、body 借用） | — |
| 签名扫描 | aho-corasick 3.x（含 SIMD prefilter） | O(n)，字面量集天花板级 | p95 2ms 全流水线 |
| libinjection | 词法指纹 O(n) + 正则集（Aho prefilter 门控） | O(n) 均摊 | — |
| 表达式 | 线性求值，14 条 | O(rules) | — |

结论：**匹配层已在性能天花板附近，瓶颈不在速度，在覆盖**。p95 2ms 对"高性能"目标的余量在于规则面扩张时保持常数级——这决定 P2 方案的选型（见 §4）。

### 1.3 结构亮点（复盘确认保留）

- 栈分类（StackSet）在 automaton 装配期过滤，收窄零请求时开销；
- LeftmostLongest 修复了 `${` 遮蔽 `${jndi:` 的语义缺陷（log4shell 漏报根因）；
- Referer/UA 降权把 FP 从 137 压到 55（-60%），代价仅 -0.9pp 拦截；
- 静态模式规则全内存（`&'static str` + Copy hit）、Pass 判决零格式化。

## 2. 漏报/误报损失面（实测归因）

对 Normal 档 437 条放行黑样本逐条归因（启发式特征 + 抽样验证），按根因聚合：

| # | 根因 | 量级（漏报） | 证据 |
|---|---|---|---|
| L1 | **body 不进静态引擎**：插件层 `agent.is_some() && (body_limit>0 \|\| inspect_body)`（pingap-plugin/src/waf.rs:2107），无 agent 时 body 永不读取 | 186 条非幂等方法（POST/PUT/PATCH/DELETE）漏报，其中 **117 条带 payload body**（SSRF/RCE/deser/lfi 主体） | curl POST `cmd=cat /etc/passwd` → 200 |
| L2 | **query 中 `+` 不按空格解码**：`multi_decode` 只处理 percent | sqli 漏报 6 条中的 4 条 | `?id=' OR 1=1--`（`+` 形态）→ 200；`%20` 形态 → 403。实测复现 |
| L3 | **时间盲注无检测面**：`waitfor\s*\(` 要求括号，`WAITFOR DELAY '0:0:10'` 无括号形态完全漏 | sqli 2-4 条 + 潜在（sqlmap 标准载荷） | `WAITFOR%20DELAY` → 200（实测复现） |
| L4 | **JS 属性调用形态无覆盖**：`parent['eval'](...)`、`window['alert'](...)`；即使 Strict 解开 `\x65\x76\x61\x6c` 也没有任何检测面消费它 | xss 漏报 20 条的大头 | hex 样本 Normal/Strict 均 200（实测复现） |
| L5 | **needle 覆盖薄**：CRLF 仅 2 条 needle、SQLi sev5 仅 2 条、缺敏感文件目标（`/etc/passwd` 只能靠 `../` 的 sev4 弱命中）、Python 代码注入 token（`chr(`、`print`）缺失 | lfi 17、rce 10、crlf 3（Strict 升级后才 60%） | needle 分布统计（113 条） |
| L6 | **评分无联合升级**：`../`（sev4）+ 敏感路径同现只累 8 分，远低于阈值 40；多个弱信号无相乘机制 | lfi/traversal 类系统性漏 | `../../../etc/passwd%00.png` → 200 |
| L7 | **JSON/嵌套结构不解包**：非表单 body 作为整 blob 扫描，不提取 JSON 键值独立解码；libinjection 对 JSON 值内 SQLi 失效（Picus 公开绕过面） | deser/ssrf POST 类 | 架构事实 |
| L8 | 混淆解码分层开启：`\xHH` 还原 Strict-only，Normal 放弃一层归一化 | 与 L4 叠加 | — |

误报面（Normal 55 条）：触发点绝大多数在 query/path 本身——搜索词含 `union select`/`and 1=1`、遥测 URL 随机串触发 libinjection。剩余 FP 需要**参数名感知**与 **needle 信任度分级**（如把 `union select` 从 sev5 needle 降为组合信号）而非继续降权 header。

## 3. 业界对标

| 机制 | 代表实现 | PingWAF 现状 | 可借鉴 |
|---|---|---|---|
| 语义化检测：tokenize → 语法结构匹配 | SafeLine 雷池（词法/AST/威胁模型） | 只有字符串 needle + 正则 + 结构容器启发 | 轻量 token 归一化：按语法角色给关键词赋分，而非裸匹配（§4-P2） |
| 异常评分 + PL 分级 + 变换链 | OWASP CRS v4（Coraza/ModSecurity） | 已有评分/PL/transform，缺参数名感知与排除机制 | 规则级参数名 exclude；libinjection 只作加分不作一票否决（现已如此） |
| ML 评分分档 | Cloudflare attack score（1-99 四档） | ScoreClass 四档（规则推导） | 短期可落地：把"多弱信号组合"语义化进评分（L6 联合升级是它的确定性近似） |
| label 管道 + count 灰度 | AWS WAF（rule group+label）、CF observe | 规则命中即影响判决 | DSL 加 label/count 动作，新规则灰度上线（误报治理基建） |
| 正则引擎扩容 | Hyperscan/Vectorscan（Suricata 默认 MPM） | aho-corasick（113 needle）+ regexset（~15 条） | 千级规则时换 Vectorscan 或字面前缀预过滤；当前规模 AC 已够 |
| libinjection 补强 | CRS 正则链兜底 + 自有指纹扩充 | 已有 7 条强正则兜底 | JSON 深层递归解码（L7）是对它最直接的补强 |

## 4. 演进方案（按优先级）

> **落地状态（2026-10）**：P0 四项已全部实现并经 waf-bench 全量复测验证——Normal 33.1%→36.5%，Normal+body 38.1%（FP 0.21%→0.23%），Strict 37.8%→51.1%，Strict+body 63.8%（FP 1.98%）。实测明细见 `waf-benchmark-report.md` §10。

### P0 缺陷级修复（低风险，预计 +10~12pp 拦截）——已落地 ✅

1. **`+` 按空格解码**（L2）：`parse_query`/`parse_form_body` 的 value 解码在 percent 前先做 `+→space`。实测堵 `id=%27+OR+1%3D1--`、`waitfor+delay` 等漏报形态。
2. **静态模式开启受控 body 检测**（L1）：waf.rs 的 body 读取门控改为「日志采集仍需 agent，检测只需 `inspect_body=true`」，静态部署不再漏 POST 攻击。开 body 后 Normal 36.5%→38.1%（+0.02pp FP）。
3. **needle 补齐与 sev 升级**（L3/L5）：时间盲注/文件读写 SQL-004~009 sev 4→5（单命中 critical）；补无斜杠变体 PT-013/014/015 解除 AC 非重叠遮蔽（lfi 32%→68%）；补 CI-026~031 语言级调用、CRLF-003/004 特异头名。
4. **JS 括号调用结构检测**（L4，Strict-only）：`detect_js_call` 识别 `parent['\x65val'](…)` 形态，Strict xss 33.3%→80%（14 条全为此类）。
5. **配套误报治理**：Normal 下 body 中反射类家族（SQLi/XSS/CI）降为弱信号（sev≤2 不 critical），XXE-001 `<!doctype` 5→3；否则白样本 xss 类误报 46%、xxe 类 100%。

### P1 检测面扩展（中风险，预计再 +3~5pp、FP 可控）——已落地 ✅

4. **JSON 递归解包**（L7）✅：`unpack_json` 以 `serde_json` 解析 JSON body（限深 6 层/值长 4KB/最多提取 64 值；深度预算覆盖埋点 JSON-in-JSON 三四层嵌套），成员 string 值按「离散输入字段」独立进解码+扫描；原 body 保留为 blob 走弱信号。`Content-Type` 含 json 或内容形态判别双入口，同时解决 `\u003c` 转义混淆（serde_json 解析后天然还原）。**字符串成员本身是序列化 JSON 时就地再解包并替换容器**（`unpack_string_json`：埋点 icon/载荷内嵌 JSON；纯数字/布尔成员也产出，保证替换语义；深度预算拒绝时不替换容器避免丢值）；表单字段值同语义（`param={"add":5,"delete":0}` 不再踩 libinjection quote-keyword）。
5. **JS 调用形态检测**（L4）✅：`detect_js_call` 落地为 Strict-only（`parent['eval'](`、`this["constructor"]["constructor"](`、hex 转义变体），Strict xss 33.3%→80%。hex 解码未扩到 Normal（`\x` 标记值在 Normal 的收益面为零——该形态样本全部被 Strict 语义检测覆盖，Normal 扩面只增误报不增拦截）。
6. **联合评分升级**（L6）✅：由 P0-3 的 PT-013/014/015 敏感文件 needle（sev5 critical）提前化解——「遍历前缀 + 敏感文件」复合形态直接单命中拦截，无需组合规则。
7. **CRLF/SSRF needle 扩面** ✅：CRLF 分源 critical 收敛为**头名注入形态**——解码值中 CRLF/CR/LF 混排（`\r\n` 与 `\r\r\n\n` 规避等价处理）后紧跟 `name:` 头名形态才 critical（query/path/header/cookie 任意面）；裸多行文本（表单多行输入回传 query、散文）只评分不拦（白样本实测：百度翻译多行 query、mathb.in 文档、StackBlitz 代码文件均为此形态）。body 面始终只评分。SSRF 补回环变体 SSRF-013~017（`localhost`/`127.0.0.1` sev4、`0x7f000001`/`2130706433`/`0177.0.0.1` sev5）与 CI-032~037（`invoke-expression`/`iex (`/`cmd /c`/`powershell -enc`/`system(`）。
8. **SQL union-select 语义门**（P2-8 的第一步落地）✅：`sqli_union_statement_shaped` 判定解码值是否具备注入语句结构特征（引号破出 `['"`]union`、常量探测 `union select <数字/引号/null>`、注释终止符/FROM 子句）；四特征全缺的 `union select` 命中（needle SQL-001/002 与 libinjection union-select 指纹）在 Normal **零分跳过**（needle 与 lib 指纹描述同一字符串，镜像多面不放大），压掉搜索短语类误报（`site:x.com union select 关键词怎么用` 是 FP 大头，sqli FP 23.9%→1.5%）；Strict 不设门（该档即激进）。
9. **弱信号评分语义修正** ✅：两轮实测迭代后的最终形态——(a) 降权命中仍进 family 子评分（sev2→24），**三轮实测证明完全脱离 family 会漏掉 Referer/UA 承载的真实反射攻击**（DVWA 型 3 个独立弱特征过门样本，拦截率 -6pp）；(b) 无语句结构的 `union select` 短语命中改为**零分跳过**（needle 与 libinjection 指纹同现只描述同一字符串，镜像多面不放大，Pass 快路径零开销）；(c) `FIELD_STRONG_MAX_LEN`（256B）：离散 body 字段解码值超长按 bulk 内容弱信号化——粘贴的代码/文档（mathb.in 7KB 数学文档、StackBlitz 源码文件）常含 `<script>`/引号关键词/CRLF 样板，短载荷（真实注入 <256B）不受影响。
10. **script-URI HTML 上下文门 + 分源语义** ✅：`xss_script_uri_html_shaped` 判定值内是否具备 HTML 标签结构（`<svg onload=…>`、`"><img …>`）——真注入需要标签上下文执行，遥测埋点把 DOM 属性原样序列化进 JSON（`{"href":"javascript: void(0);"}`，beacon 类 16 条误报全部此形态）。语义：**body 源**无标签结构的 `javascript:` 命中（XSS-007 + libinjection js-uri 指纹）在 Normal 零分跳过——blob 与解包成员的镜像不能靠弱信号累加踩过 XSS family 门（PINGWAF-1003）；**query/cookie/header 源**的裸 `javascript:` 保留 critical（`?url=javascript:alert(1)` 是真实反射形态）。Strict 不设门。

### P2/P3 确定性扩面（第三轮实测驱动）——已落地 ✅

对 Strict+body 档 238 条漏报全量归因（b64 递归解码 + URL 双轮 + `\u` 反转义三轮脚本迭代 + 6 个疑问样本 spot 回放确认引擎缺口）后落地的确定性方案：

11. **SQL 强正则扩面 + comment-stripped 重扫** ✅：10 个强检查抽为 `sqli_strong_checks` 共享函数（直接 pass 与注释剥离重扫复用）。新增 bare-select（裸 `SELECT … FROM` 表枚举，列名清单形态要求，散文 `select a gift from our store` 不触发）、blind-probe（`SELECT CASE WHEN (…) THEN …`/`TO_CHAR(1/0)` Oracle 盲注词典）、truncated-tautology（`1' or ''='` 截断恒真尾）、inline-comment 重扫（`OR/**/"1"="1"` 关键词注释切分）。三个新正则各带语义门：blind-probe 的泛化 `case when…then` 备选**要求 SQL 操作符前缀**（select/and/or/`||`/`;`/引号/括号）——散文 "in the case when … then"（waf-bench 白样本 7 条）不触发；bare-select **跳过完整查询子句**（WHERE/GROUP BY/ORDER BY/HAVING/LIMIT/OFFSET/JOIN）——词法上不可分的合法查询类（`q=SELECT * FROM users WHERE slug='x' LIMIT 1`）保持通过，与 P1 散文 union-select pin 同一取舍。
12. **base64 值级展开**（normalize）✅：charset 快检 → core≥12 → 补 padding → STANDARD 解码 → UTF-8+可打印率 >90% 门（md5 hex 解码为二进制被拒），解码值含 `%` 再走一层 `decode_value`，形似 JSON 则 `unpack_string_json` 替换容器（quote-keyword FP 防线语义复用），否则以 `name.b64` 附加值进扫描面（blob/超长弱信号门自然兜底）。双层递归（`B64_MAX_DEPTH=2`）覆盖 JSON+\u 嵌套的 b64 包装家族。
13. **overlong UTF-8 字节级还原** ✅：`urlencoding::decode` 遇 `%C0%BC`（无效 UTF-8）整体 Err 导致后续载荷不可见；重写 `multi_decode` 为字节级 percent 还原 + `bytes_to_scannable`（C0/C1 lead 按双字节规则折叠，剩余 Latin-1 映射），`<C0%BCscript%3E` 类绕过面闭合。UTF-7 明确不做（现代浏览器已废弃，收益面为零）。
14. **needle/正则扩面** ✅：PT-016 `win.ini` sev5；CI-038~042（`|whoami` sev5、`;whoami`/`|uname`/`` `uname` ``/`;uname` sev4）；DZ-012~015 OGNL/Struts2（sev4，配合 deser-shape 分级）；XSS-020/021 prototype 链/JSFuck + `XSS_DOM_CHAIN` 正则（`constructor.prototype` 调用链）；CI-043 `getruntime().exec` sev5——OGNL/SpEL RCE 的载荷核心（`@java.lang.Runtime@getRuntime().exec(`、`T(java.lang.Runtime).getRuntime().exec(`），Normal 即 critical。
15. **deser/OGNL 形态分级** ✅：`detect_deser_shape`（OGNL 静态调用 `@class@method(`/PHP 序列化 `O:\d+:"`/`s:\d+:"…";s:\d+:"` 记录形态）在 Normal sev4 评分（OGNL 对非 Java 站点无解释面）、Strict sev5 critical（deser 家族在 strict 档整体 critical）；弱信号门（meta header/body blob/超长）与 needle/lib 门一致。
16. **P2 实测驱动的语义门回修**（两轮 bench FP/回退归因后）✅：SQLI_TAUTOLOGY 收紧为「数字自等/引号对/1<>0」三形态——`word = string` 比较（Lucene/API 过滤语法 `author=="CT Stack"`）不再是注入信号；SQLI_QUOTE_KEYWORD 从「任意距离引号+关键词」收紧为**邻接判定**（引号后 `\s);` 容差内直接跟关键词）——缩写撇号（"couldn't select"）与 b64 词表长距误触发闭合。收紧连带暴露两类 P1 靠宽松 quote-keyword「误打误撞」拦截的攻击面，补确定性检测承接：**bool-subquery 强检查**（操作符前缀子查询 `and (select …` / `N=(SELECT …)` 比较，PortSwigger 布尔盲注家族）、**SQL-020 `utl_inaddr`**（Oracle 报错注入）、**CI-043 `getruntime().exec`**（OGNL/SpEL RCE 载荷核心，承接 6 条 b64 包裹 OGNL 黑样本在 Normal 的拦截）、**CI-044 `securegroovy`**（Jenkins 沙箱绕过端点）、**DZ-016 `getclass().forname`**（EL/SpEL 反射 gadget 链，Nexus CVE-2020-10199/10204 家族）。回修后 16 条新增误报全部消除、59 条新增拦截零回退、8 条 PortSwigger 盲注重新拦截，并顺带压掉 18 条 P1 遗留遥测类误报。

### P4 第五轮：解码链补齐 + strict FP 治理——已落地 ✅

post7 归因（strict+body 漏报 147 条 + strict 档 105 条 FP 全量脚本归因）驱动的第五轮，两条主线：

17. **解码链补齐** ✅：(a) b64 解码层含 `\u`/`\x` 转义时无条件还原（b64 包裹的 JS/Java escape 二次混淆）；(b) JSON 结构位置裸控制字符剥离重试（`{"policy":"<b64>"}` 混入 `\r\t\x00` 后 serde_json 解析失败导致成员不可见）；(c) `parse_query` 对 `param={"json":…}` 值就地解包（对齐 form 语义）；(d) HTML 符号实体表补 27 个（`&colon;`/`&semi;`/`&sol;`/`&lpar;`/`&Tab;`/`&NewLine;` 等——DOM 序列化常用的无分号变体）。
18. **needle 扩面** ✅：宽命令分隔 CI-045~072（`;|` + 反引号 + `||` 前缀的 whoami/uname/ping/curl/wget/sleep/echo）、CI-078 `eval(atob(`、LDAP 注入 CI-080~082（`)(uid=`/`)(|(`/`*)(objectclass=`）、JSFuck XSS-022 `[(+{}+[])`、PT-017 `web-inf`/PT-018 `portal_inc.lua`、SQL-021 Postgres `COPY … TO PROGRAM '`（sev5 全档 critical）。
19. **strict FP 治理** ✅：PINGWAF-1051（长 URI）Block→Log；strict CRLF blanket-critical 摘除（body 源多行文本 + 非头名形态不 critical）；path 源 CI/Deser 形态改走 `add_severity_hit` 旁路（矩阵参数 `/foo;cat=…` 是存储 URL 语法不是 shell，保持聚合分但不进 RCE 子分桶）；strict js-call 对非字段 body blob 零分跳过（收集页面文本的括号调用是散文）。
20. **post8 归因回修（第三轮语义门）** ✅：strict+body 回退 42 条与残余 69 FP 逐条归因后——(a) **CRLF 同伴门**：strict 下同值携带 CI/PT/Deser/SSRF 家族特征时 CRLF 恢复 critical（换行走私载荷 = 真实 response-splitting 流量，纯多行文本无同伴），追回 17 条回退；(b) **into-file 语句形态门**：`sqli_into_file_statement_shaped` 要求 `into (out|dump)file '目标'` 引号目标形态，SQL-008/009 needle 与 libinjection `into-file` 指纹两侧同语义（对齐 union-select 门），6 条搜索短语 FP 消除；(c) PINGWAF-1021 摘压缩包后缀（`.zip/.tar.gz` 是普通下载资源，仅保留 bak/backup/old/swp/sql），5 条 FP 消除；(d) js-call blob 豁免贯彻到 RCE 子分（`add_expr_hit` 的 rce+48 会让 PINGWAF-1061 重新拦截——豁免必须是零分跳过而非仅降 critical），16 条 FP 消除。


### P3 语义架构演进（高性能高命中低误报的地基）

17. **token 归一化语义评分**（SafeLine 思路的确定性近似）：解码后对每个值做轻量词法切分（复用 SQL 指纹器），按语法角色计分：`union+select`（两个 keyword 相邻）> `union`（孤立）> 普通词。比信任度分级更通用，且 O(n)；P2-11 的语句结构门已覆盖其最高价值场景（union select 搜索短语 FP），剩余收益面在深层混淆样本。
18. **label 化管道 + count 灰度**（AWS/CF 模式）：DSL 增加 `label("...")`/`count` 动作，规则命中只打标不判决，管道末端按 label 组合统一裁决；新规则默认 count 上线观察。这是后续所有规则扩张的误报保险，也是 strict 档 2.38% 误报的正解。
19. **参数名感知排除**：站点/规则级 `exclude`（按参数名/路径），CRS `ctl:ruleRemoveTargetById` 的静态版；把误报治理从改规则变成加白名单。
20. **Vectorscan 预留**：托管正则规则超 ~500 条时把 `matches` 编进 Vectorscan 数据库做第二层（AC 粗筛 + 正则精确认证）；当前 15 条正则的 regexset 路径不动。

### P5 第六轮：libinjection 指纹长度门 + script 闭合标签门——已落地 ✅

post9 残余 46 条 strict+body 误报逐条归因（libinjection tautology/quote-keyword ×15、XSS 反射 ×13、同伴门反噬 ×6、收集 HTML/playground ×8）后落地的两道确定性语义门：

21. **libinjection 指纹长度门** ✅：`tautology` 指纹 + 值 >32B 且无 `comment-terminator` 指纹 → 搜索短语零分（真实恒真探测极短，散文引用 "1 and 1=1 is a very basic mathematical operation" 不拦；带注释终止符的长盲注保留 critical）；`quote-keyword` 指纹 + 值 >256B → 搜索短语零分（词表文档远距撇号误触发，真实长 exfiltration 带 UNION 子句自有关键指纹）。658 黑样本全量 triage 回归：第一版门误伤 11 条（`tautology,comment-terminator` 指纹长盲注 ×9、`<script+…>` 的 `+` 未解码 ×2），收紧后 **527 条拦截全部保持**。
22. **`<script` 开标签形态门** ✅：`xss_script_tag_shaped` 区分真实标签与文字引用——XSS-001 needle 与 libinjection `script-tag` 指纹两侧同语义。`1<script`、"binary<script is incorrect" 是搜索词/文章标题而非可执行标签，全档零分跳过；属性形态 `<script src=…>`（含 `+` 代空格的 URL 形态）与紧凑开标签保持 critical（P6 修正：紧凑 `<script>alert(1)</script>` 是真攻击形态，见第 23 条）。

预期效果：strict+body 误报 46→22（0.14%→**0.07%**），全部四配置 FP 压到 0.07% 量级；剩余 22 条为 xray POC 定义模板、嵌套 URL 埋点、HTML playground body 等载荷定义/收集类，归 P6+ 语义与 label/count 灰度基建。

### P6 第七轮：拦截侧确定性扩面（138 漏报全量归因驱动）——已落地 ✅

post9 strict+body 口径 138 条漏报全量分层后的确定性方案（12 条链路差异定性 + 57 条 Monitor 复核 + 68 条零信号解码聚类）：

23. **`<script` 开标签双形态语义（P5 门缺陷修正）** ✅：P5 门正则 `<script[\s+>]…>` 的 `[^>]*>` 闭合要求使紧凑 `<script>alert(1)</script>` 全零分跳过（XSS-001 与 libinjection 两侧同时漏）。重写为双正则：`SCRIPT_TAG_ATTR = <script[\s+][^>]*>`（属性形态，全源）+ `SCRIPT_TAG_COMPACT = <script>`（紧凑开标签，仅 `compact_allowed` 反射源 query/path/header/cookie）——body 源紧凑 `<script>` 是合法 HTML 上传（playground 白样本类），属性形态仍覆盖。
24. **SQL/CI needle 扩面 ×5** ✅：SQL-022 `cast((select`（PortSwigger 嵌套 CAST 外带，8d/78）、SQL-023 `extractvalue(`（Oracle XPATH 报错注入，9d/63）、SQL-024 `or 1 limit`（截断恒真尾，3e/ba）、CI-083 `ping -c `（链式 ping 探测，64/b5）、CI-084 `#context.get(`（Struts2 OGNL 上下文变量链，ff/67），全部 sev5 critical。
25. **query key 进扫描面** ✅：`?redirect:%24%7B%23a%3D%23context.get(...)` 的 `%3D` 编码 `=` 不算 pair 分隔符——整串是 key、value 为空，OGNL 载荷对全部检测器不可见。解码 key（≤512B 上限防词表键镜像）以 `field` 形态加入 `decoded_values`。
26. **b64 展开实体解码扩面** ✅：expand_base64 的二级解码条件 `%` 扩为 `%` 或 `&#`——b64 内 HTML 实体 meta-refresh（05/4a）payload 可见。
27. **path 独立扫描循环补 search_phrase 门** ✅：P5 门只覆盖 decoded_values 循环，`normalized.path` 的独立 sev5 fast-path 循环漏加，`binary<script is incorrect` 作为 URL slug 会经 XSS-001 sev5 直接 critical。补门且 search_phrase 命中时 `continue` 零分跳过——否则 XSS family 子分 48 会经 PINGWAF-1003 兜底重新拦截（豁免必须零分跳过原则的又一实例）。

回归：172 单测全绿（新增 4 个确定性覆盖：紧凑标签反射面拦截、path 散文通过、五类 post9 漏报形态、b64 实体包裹）；658 黑样本 triage 527→539（+12 零回退）；fp46 白样本 Block 22→20（多修 2 条、零新增）。12 条 triage/回放差异定性为样本传输语义缺陷（11 条 POST 无 Content-Length，HTTP/1.1 下 body 为空，payload 无法到达服务器；1 条 GET 400），非引擎缺口。

post11 全量实测（33877 样本）：四配置**全部双向改善**——Normal 332→**341**（+9）/ FP 7→**5**，Normal+body 389→**399**（+10）/ 16→**14**，Strict 438→**447**（+9）/ 7→**5**，Strict+body 520→**531**（+11）/ 24→**22**（0.14% 目标线内连续第三轮，实际 0.066%）。strict+body 拦截率首次突破 80%，误报率的同步下降来自 path 循环 search_phrase 门在白样本 URL slug 上的放行。

### P7 第八轮：Monitor 分数不足细分 + 零信号复检——已落地 ✅

以 post11 实测漏报（而非过时的 post9 列表）重新提取 strict+body 口径 127 条漏报，三分层归因：13 条 triage 判 Block 但回放 passed/protocol_reject（样本传输语义链路差异）、54 条 Monitor（有信号但分数不足 strict 家族门）、59 条 Pass（引擎零信号）、1 条 Challenge。Monitor/Pass 两层聚类后的确定性方案：

28. **b64 展开外层长度门 16→10** ✅：`MSBhbmQgMT0y`（`1 and 1=2`，12B）藏身 JSON 成员内，落在旧 16B 外层门与 b64_decode_value 内部 12B core 门之间的盲区；charset 快检 + printable>90% 才是真正的质量门，外层门只约束工作量。
29. **needle 扩面 ×10** ✅：SQL-025 `xp_dirtree`（Postgres/Windows 文件系统横向探测）、SQL-026 `dbms_pipe.receive_message`（Oracle 时间盲注）、PT-019 `..;/`（Tomcat/F5 分号穿越，仅出现在绕过路径归一化代理的走私流量中）、DZ-017 `rO0AB`（Java 序列化魔数 `AC ED 00 05` 的 b64，ViewState/RMI/cookie 载体）、SSRF-018 `gadgets/makerequest`（Atlassian gadget 代理 CVE-2019-3403 家族，exploit 专属路由）、CI-085 `<?php`（PHP webshell 开标）、CI-086 `think\app/invokefunction`（ThinkPHP dispatcher RCE）、CI-087 `` `touch ``（反引号命令执行）、CI-088 `runphp=`（DedeCMS 模板执行）、CI-089 `*)((|`（LDAP 盲注 break 变体），全部 sev5 critical。
30. **事件处理器正则双前缀** ✅：XSS_EVENT_HANDLER 从 `\son[a-z]+\s*=` 放宽为 `(?:\s|\+)on[a-z]+\s*=`——header/path 源的 `+` 不按空格解码（URL 反射语义），`<xss+onafterscriptexecute=alert(1)>` 的 Referer 反射形态此前不可见。
31. **Referer/UA 降权的 markup 豁免** ✅：`xss_markup_shaped`（script 标签属性/紧凑开标签/事件处理器/脚本 URI 四正则）命中时 `is_meta_header` 降权不生效——浏览器只会发出合法 URL，Referer/UA 里出现可执行 markup 结构必是攻击工具反射上轮探测的回放，而「引用含 union select 的散文」的 Referer 仍正常降权。

回归：174 单测全绿（新增 2 个测试覆盖 11 类 Monitor/Pass 形态与 Referer `+` 编码事件处理器）；658 黑样本 triage 539→**576**（+32 零回退，新增命中全部来自 P7 needle 与联动跨过 strict 家族门的样本）；fp46 白样本 Block 20（与 P6 一致）零新增，且全部在 post11 回放中同样被拦。

post12 全量实测（33877 样本）：四配置拦截 **+21~+28**（P7 为八轮中单轮增益最大）、误报全部持平零新增——Normal 341→**366**，Normal+body 399→**426**，Strict 447→**468**，Strict+body 531→**559**（80.7%→**85.0%**）。P7 三类修复分别承接独立漏报族：b64 外层门放宽承接 JSON 成员内短载荷、10 条 needle 承接 PHP/ThinkPHP/DedeCMS/LDAP/Tomcat/Oracle/Atlassian 各 POC 路由、markup 豁免承接 Referer 反射事件处理器。

### P8 第九轮：零信号残余的四个确定性形态——已落地 ✅

post11 漏报经 P7 后仍开放 84 条（44 Pass / 37 Monitor / 2 链路 / 1 Challenge），Pass 批量抽查定位出四个引擎结构性缺口：

32. **引号包裹 JSON 解包** ✅：`id='{"id":"L2V0Yy9wYXNzd2Q="}'` 的单引号外壳是 SQL/字符串拼接产物（后端会剥壳再解析），`looks_like_json` 首字符检查失败使 JSON 成员整体不可见。`unpack_string_json` 入口增加一层同引号剥壳重试，七个调用点（query/form/JSON 成员）共享同一入口全覆盖。
33. **needle ×2** ✅：SQL-027 `updatexml(`（MySQL 报错注入外带核心，Drupal form 数组参数名注入形态 `name[0 or updatexml(…)%23]`——key 扫描面 P6 已就位，缺的只是 needle）、CI-090 `allow_url_include`（PHP-CGI ini 覆盖 CVE-2024-4577 族，`?-d+allow_url_include%3Don` 经 key 扫描命中），全部 sev5。
34. **path 段 tautology** ✅：libinjection 源门排除 Path（路径是存储 URL 语法），`/api/products/123 and 1=1/reviews` 整体 34B 又超 tautology 的 32B prose 门。`path_tautology_segment` 对 `/` 分段独立跑 `detect_sqli`（段 5~32B 与 prose 门语义一致——探测段极短、散文引用极长），命中走 sev5 critical。
35. **`\u0006` 控制符嵌套与原始 `%ac%ed%00%05` 魔数暂缓**：`\u0006`-分隔的多层编码数组（17/12 等）与 URL 编码原始序列化字节（70/62）需要解码器结构性扩展，收益单样本成本高，归 P9+。

回归：175 单测全绿（`p8_zero_signal_forms_block` 覆盖四形态 + prose slug 放行负样本）；658 黑样本 triage 571→**575**（+4 零回退，四个新形态各承接一条）；fp46 白样本 Block 20 持平零新增。post13 全量实测：见《waf-benchmark-report》§17 P8 行。

### P9 第十轮：b64 传输门放宽 + Monitor 形态升级——已落地 ✅

输入两路：post13 strict 漏报 95 条全量归因（批次一）+ P8 遗留 Monitor 22 条逐条复核（批次二）。95 条中 18 条为无 Content-Length 的 POST/PUT（bench 回放器与 triage 直读文件的链路差异——合规客户端不发 body，物理不可拦，精确化取代 P8 归档的「13 条」口径）；其余 77 条批量抽查以 4 个代表性样本走 python 模拟解码链逐层对照，定位出**唯一共同断点**：`B64_MAX_VALUE_LEN=4096`。

36. **B64_MAX_VALUE_LEN 4096→16384** ✅：transport-wrapped XML/JSON 攻击体（5.1KB wire 值解出 3.8KB JSON，OGNL `#context.get('com.opensymphony.xwork2')` 以 `\u` 转义嵌入）整体落在门与检测器之间。charset + printability 双质量门仍在 `b64_decode_value` 内部，扩的是尺寸上限不是质量标准。
37. **控制符剥离 filter→空格替换** ✅：obfuscated transport 的 JSON 结构位携带裸控制字符（key 与冒号间杂 CR、闭括号前 NUL），严格 parse 拒收后重试被跳过；原 filter 直接删字符会把 `droP\ntable` 粘成 `droPtable` 丢掉词边界——替换为空格保留 token 边界。
38. **SQLI_UNION_COMMENT_SPLIT 粘注释拆分** ✅：`unION#filler\nselECT` 形态（`union` 与 `select` 被 `#`/`--` 注释 + 填充分离）。`#`/`--` 必须**粘**在 `union` 后——诚实散文与教学 SQL 注释前总有空格，粘注释即作者混淆；`select` 须在 64 filler 字节内出现；右缘接受数字或任意非字母（攻击者删换行把 keyword 粘到后续 token），`selection` 无法触发。曾设计的行注释剥离重扫（`UNION\n-- x\nSELECT` 教学 SQL 剥注释后 union/select 相邻）因误报面被否决删除，51/09 实际由本形态命中。
39. **Monitor 三形态升级 + Path 反引号对** ✅（22 条非 CRLF Monitor 逐条归因后的确定性族）：`ci_backtick_interleaved`（`;wh``oami` 反引号空对插空绕过分号命令分隔）；Path 源成对反引号（URL content 不携带未转义反引号，成对即命令替换 `/ax--exec=`id`--remote`）；`ssrf_protocol_smuggling`（ldap/gopher/dict:// + 换行 = 协议走私，纯 ldap URL 无换行保持放行——监控集成探测是合法场景，有负样本护栏）；`pt_remote_backslash_include`（`http\..\` 远程包含反斜杠形态）。暂缓 3 族：SSTI `\B{233*233}`（f7/8b 需新表达式形态族）、deser-shape Referer 降权豁免（b1/71 档位设计权衡）、XSS-019 DVWA 反射族（需响应面知识，静态检测面之外）。

回归：180 单测全绿（5 个新测试：`b64_wire_over_old_gate_ognl_blocks`、`union_comment_glued_split_blocks` + 散文负样本 `union_teaching_sql_with_spaced_comment_passes`、`monitor_upgrade_shapes_block` 四 case + `ssrf_ldap_url_without_newline_stays_monitor`）；658 黑样本 triage 575→**592**（+17：13 条 b64 门 + 4 条 Monitor 升级，零回退；9 条大 body 噪声样本命中均为双层 b64 埋 OGNL/script-tag 的多规则交叉确认真实攻击）；fp46 白样本 Block 20 与 P8 集合完全一致零新增。post14 全量实测：四配置 +3/+10/+3/+16 零回退、FP 全部持平（5/14/5/22），strict+body 85.6%→**88.0%**，p95 持平（静态 4ms / body ~3s¹）——见《waf-benchmark-report》§18 P9 行。

### P10 第十一轮：key 扫描面完整化 + 双扩展上传检测——已落地 ✅

输入：post14 strict+body 开放 79 条（76 passed + 3 protocol_reject）。18 条无 Content-Length 的 POST/PUT 维持 P9 链路差异归档；61 条 triage（3 Block / 31 Monitor / 27 Pass）逐族归因，两个确定性缺口：

40. **key 扫描面完整化** ✅（三处缺口一次闭合）：其一，P6 只给 query key 加了扫描面，**form key 完全不进扫描**——Drupal `name[0 or updatexml(…)]=…` 报错注入与 `mail[#post_render][]=exec` AJAX RCE 两族全靠 key 走私；其二，key 解码只跑 percent（`multi_decode`），`\u0025\u0032\u0035…` 转义洋葱粘在 key 位置时检测器只看到转义形态；其三，key 扫描上限 512B——一条 564B 的 key-only 参数（整体是 b64，解出 `%2528select extractvalue(…)` 再两层 percent）恰好滑过。修复：query/form 的 key 统一走完整值链 `decode_value_form`（percent + entity + 转义还原）、form key 补齐独立 push、上限提到 1KB；另修 `decode_value` 单遍缺陷——escape 还原（`\u0025…`→`%25`）新暴露的 percent 层现在补一轮有界复解，值与 key 同享。
41. **path 双扩展上传检测** ✅：`/uploadfiles/apache.php.jpeg` 形态（Apache/IIS 多扩展解析滥用，图片后缀伪装可执行 handler）。path 尾锚定正则（可执行扩展 + 1~5 字符尾缀），中间路由段不触发；`/static/app.min.js`、`/assets/logo.png` 负样本护栏。**首轮正则把 `exe|dll|sh|bat` 一并列入危险扩展，post15 bench 预览即暴露 2 条 FP（`vendor.dll.js`、`vendor.fee62103.dll.js`）**——webpack DLL 产物命名约定（`<name>.dll.js`）远大于攻击面，且黑样本全部是 php 族（`apache.php.jpeg` ×2），桌面二进制扩展不构成服务端执行风险；收窄为服务端脚本族 `php\d?|phtml|asp|aspx|jsp|jspx|cgi|pl|ashx` 后白样本语料全量预检零命中、黑样本拦截无回退。方法论沉淀：**新形态检测器上线前先对白样本语料跑一遍正则预检**，一轮 grep 换掉一轮 1.5h bench。
41b. **form key 扫描面 × js-call 形态门博弈 + Drupal render-key needle** ✅：form key 进扫描面（40 条修复）后，js-call 的 `JS_BRACKET_CALL` 尾字符类 `[\[(]` 把 `subPayType[deduct][]` 的裸双下标当成 `this["a"]["b"]` 链式调用（第二个 `[` 匹配尾类）——strict-body +3 FP（腾讯云账单族 ×3）。post14 全量里 js-call **零命中**（不承担任何黑样本拦截），语义收紧零成本：尾是真调用括号 `(` 保持内容无关（`global[\x65val](cmd)` 裸形态保留）；尾是链式下标 `[` 时要求引号段（`this['constructor']['constructor']`）。`x[a][b](` 裸真调用仍在检测面。**收紧的代价由第二轮 bench 暴露**：ff/fb（`mail[#post_render][]=exec&mail[#markup]=id`）首轮靠 js-call 裸链尾 `[` 误打误撞命中，收窄后回 Pass——其真实信号是 Drupal render-array key（Drupalgeddon 2/3 族），补 CI-091~095 五条 sev5 needle（`#post_render/#pre_render/#lazy_builder/#markup/#elements`，白样本语料预检零命中），ff/fb 恢复 Block（CI-091+CI-094 双命中）。教训：**检测器行为变化要用「该变化放走的样本」验证语义归因**，碰巧拦下的样本不代表检测面正确。引擎层负样本：form body 数组参数 Pass + 引号链 key Block；正样本 `drupal_render_key_form_rce_blocks`。

归档不修：3 条 protocol_reject（HTTP 解析层 400，非 403/503 口径）；ff/67 是 S2-045 OGNL 全量藏在 URL `#` fragment 后——数据面语义 uri 剥 fragment，真漏报但修复需 plugin 把 `uri.fragment()` 作为独立值传入（跨 crate 接口改动），样本面黑 1 / 白 0，归 P11+；Monitor 31 条维持已知暂缓族（XSS-019 反射 ~10、CRLF 单信号 sev4 ~12、libinjection quote-keyword SSTI 2、deser-shape Referer 1、长 URI log 1、组合 score9 1）；Pass 残余 21 条为多层转义长尾。

回归：183 单测全绿（`key_only_b64_and_escape_onions_join_scan_surface`、`key_only_b64_sqli_and_double_exec_extension_block` 含双扩展白形态负样本、`drupal_render_key_form_rce_blocks`）；61 条 triage Block 3→**9**（+6：双扩展 ×2、key-only b64、转义洋葱、Drupal form key RCE ×2，全部为真实攻击特征）；fp46 白样本 Block 20 持平零新增。post15 全量实测：见《waf-benchmark-report》§19 P10 行。

### P11 第十二轮：B 类漏报归因 + b64 值链三处断点 + needle 扩面——已落地 ✅

输入：post15 strict+body 开放 73 条（70 passed + 3 protocol_reject，Monitor 清零）。**口径修正先行**：73 条中 18 条是无 Content-Length 的 POST——真实链路 body 永远不会到达（RFC 7230：无 C-L 且无 T-E 即空 body），triage 直读文件才看得到 payload，bench 放行是正确的链路语义，**不是漏报不计修复面**。方法论：triage（文件直读）与 bench（真实 HTTP）对无 C-L POST 必然分歧，**先按 C-L 分类再归因**。B 类真漏报 55 条 = 51 Pass/Monitor + 3 protocol_reject + 1 Challenge，逐条归因后落地：

42. **b64 层控制符归一** ✅：b64 传输填充走私裸控制字符（`OR\0/* \r…` —— NUL 粘在 keyword 后），90% printability 门放行（占比低），下游 SQL 词法全断——libinjection 丢 token、`\bor\b` 正则失配、注释剥离重扫同样被 `\0` 卡在 `or` 与 tautology 之间。修复：`expand_base64` 解码后统一把 ASCII 控制字符（保留 `\t\n\r`）替换为空格——与 P10 JSON 控制符重试同一取舍（空格保 token 边界），覆盖 whole-value 与派生层。样本 66b7（NUL 缀于大小写混淆 keyword 与引号 tautology 之间的畸形传输值）恢复 tautology + comment-stripped critical。
43. **quoted-run b64 提取** ✅：`\u` 转义洋葱的 payload 藏在 JSON 数组字符串字面量里（`["tag","\u004d…"→"KSk7…="]`）——whole-value b64 不适用、escape 解码后经典 b64 run 裸露在引号之间。修复：`expand_b64_substrings`（**Strict-only**——暴露 run 的 escape pass 本就 Strict 专属），门条件「b64 run ≥16 且紧贴双引号开合」——UA token 与 header blob 不满足引号邻接，hex 哈希/驼峰词由 charset + printability 门拒收；白样本裸 run 占比 90%（UA `AppleWebKit/537` 即命中）证明引号门是必要的形式约束，裸提取不可行。每值 ≤4 push 有界。
44. **needle 扩面五条** ✅（白样本语料全量预检零命中后上线）：CI-096/097/098 ASP 一句话木马（`<%eval`/`<%execute`/`eval request(`，b64 传输解出即拦）、CI-099 `file_put_contents`（远程投毒参数值形态）、XSS-023 `+ADw-`（UTF-7 编码 `<` 固定前缀）、XSS-024 `alert(1)` 字面（泛 `alert(` 维持 sev3 散文豁免，精确字面在良性语料零出现）。另有 chr() 码点链 shape（`chr(121)+chr(101)+chr(115)`，两连 `chr(N)` 即注入构建形态）以 `ci_chr_chain` 正则入 ci-shape critical。
45. **b64 非 canonical 尾位容错** ✅：a2/1f 两层洋葱悬案解开——首层 214 字符 whole-value b64 末组 `S0`（`0`=`0b110100`，低 4 位冗余位非零）是**非规范 base64**：python `binascii`/Java 宽松解码器接受，Rust base64 crate 严格模式拒绝（`InvalidLastSymbol`）——后端能解开的传输层 WAF 解不开，整条 payload 从未到达检测面。修复：`b64_decode_value` 换用 `with_decode_allow_trailing_bits(true)` 引擎；charset + printability 门仍是质量过滤，尾位宽松只扩大到达门的面。
46. **裸 waitfor strong check** ✅：洋葱终层 `));wAITfor` + 注释填充词表——现有 `SQLI_DANGEROUS_FN` 要求 `waitfor\s*\(`，而真实 T-SQL `WAITFOR DELAY` 语句从不带括号（原正则实际永远匹配不到真实时间盲注形态）；`SQLI_FUNCTIONS` 词表有裸 waitfor 但仅参与计分不判结构。修复：`\bwaitfor\b` 以 `SQLI_WAITFOR` 入 strong；白样本全量预检零命中（T-SQL 独有语句关键字，HTTP 面无诚实用途），keyword prefilter 早已含 `waitfor`、成本有界。

归档不修：5c/aa 内层为 `));…--` 破坏片 + 词表噪声（静态语义弱，暂无组合门）；信息泄露/未授权 API 族（Coremail dumpConfig、Rocket.Chat callAnon、Joomla config API）与空参数探测起手（`?id=&Submit=`）超出通用语义静态面；2 条 waf-ce 随机词假黑样本。protocol_reject 3 条与 Challenge 1 条维持口径归档。

回归：189 单测全绿（新增 6：`b64_transport_control_chars_no_longer_split_sql_keywords`、`quoted_b64_run_inside_json_array_unwraps`、`python_chr_chain_blocks`、`utf7_and_alert1_probes_blocks`、`asp_one_liner_webshell_blocks`、`noncanonical_b64_waitfor_onion_blocks`）；a2/1f 全链路悬案（非 canonical 尾位 + 裸 waitfor 双断点）解开转 Block；10 条目标样本 triage 0→9 Block；全量 bench 见《waf-benchmark-report》§20 P11 行。

### P12 第十三轮：Java 序列化魔数原始字节传输面——已落地 ✅

输入：post16 strict+body 开放 53 条。逐条归因第一项落地：

47. **Java 序列化魔数 query** ✅：`?s=%ac%ed%00%05%73%72…` 原始 ObjectStream 字节经 percent 传输——byte 还原解码器（非法 UTF-8 经 Latin-1 映射）早已把 `¬í\0\u{5}sr` 文本送进扫描面，**断点在 needle 形态**：hex-text needle `aced0005` 与 b64 transport needle `rO0AB` 都看不见这条 Latin-1 字符序列。修复：`DESER_JAVA_MAGIC` 正则（`\x{AC}\x{ED}\x{00}\x{05}sr`）入 `detect_deser_shape` 返回 `java-serialized-magic`——要求 magic 后随 `sr` 类描述符标记，把形态绑定到真实序列化流；`\u{ac}` contains 预滤保证非样本值零额外成本。Query 源非 weak → Strict critical Block / Normal sev4 计分（与 P8 b64 形态 ViewState 同层同权，互补覆盖同一魔数的两条传输面）。

回归：191 单测全绿（新增 2：`detect_deser_java_magic_in_latin1_restored_bytes`、`java_serialized_magic_percent_query_blocks`）；70/62 triage Pass→Block；全量 bench 见《waf-benchmark-report》§22 P12 行。

48. **quoted-run 单引号放宽 + 管道/git/Lua/XStream needle 族** ✅：post17 后 13 条 REAL other 漏报逐条归因出 6 个可修族。①**引号门放宽**——`expand_b64_substrings` 的引号包裹 b64 run 只认双引号，而 SQL/Python 字典值（`{'id': 'MCcg…='}`）的单引号字符串字面量同样承载 payload（710c90 族），放宽为 matching string quotes；白样本全量预检：单引号 b64 run 唯一命中族是驼峰 API Action 名（ListResourceGroups 等），解码后 printability 门拒收（11%~46%），放宽安全。②**needle 族 8 条**——紧凑 `||` 管道 DNS 链（`||nslookup `，`+`→空格解码后成立）、管道写文件（`|touch /`）、git 选项注入（`--open-files-in-pager=`/`--upload-pack=`，CVE-2019-1387 族）、Lua os 沙箱逃逸（`require('os')`/`require("os")`，APISIX 族）、XStream custom-serialization XML（`<java.util.`/`serialization='custom'`，CVE-2021-21344 族）；白样本 needle 预检 8 条零命中。**编号教训**：初版与既有 `$(cat` 命令替换族（CI-101~106）重号——details 去重按 ID（engine 1054-1058），重号不吞分但归因歧义，扩 needle 前必须 grep 既有 ID 占用；已顺延为 CI-107~112。

49. **Nexus EL 探测 + 分离 Java RCE + web.xml 值面** ✅（P13）：post18 剩余 46 条漏报按 C-L/判决精确重分层——34 无 C-L（链路伪影）、3 protocol_reject、3 注定面（Rocket.Chat callAnon 未授权 API + 2 条随机词假黑），**REAL 面 9 条**。逐条归因出 3 个 needle 族：①**Nexus EL 算术探测**（CVE-2020-10204 族，三条）——`$\A{233*233*233}`/`$\B{233*233}` 引擎特有转义变体，算术求值探测只存在于 exploit 载荷；②**分离语句 Java RCE**（Unomi MVEL CVE-2021-44227 族）——`Runtime r = Runtime.getRuntime(); r.exec(…)` 语句分离形态绕开 CI-043 连写 needle `getruntime().exec`，裸 `getruntime()` 在诚实参数值零出现；③**部署描述符探测**（Confluence macro-preview `_template`，CVE-2021-26084 探测族）——`_template` 裸形态白样本 19 条命中（Twig/Velocity 模板参数）不可用，改用值面 `web.xml`（与既有 `web-inf` 同族互补）。4 条 needle（PT-020/CI-113/114/115）白样本全量预检零命中；全部在 AC 自动机内，零新增解码面。

**剩余不可修面（P13 后）**：waf-ce 合成 XSS 洋葱 2 条（0a547696/d7b61c 同族）——解码链为 percent→\u→b64→混合实体（`&bsol;`+`&#x` 交错）→终层引号错位 `"/onerror="location=…`，b64 层后实体链需实体还原+`\u` 二轮还原才现形，且终层引号错位非真实 HTML 语法（合成探测器）；修复需 engine/normalize 深改（混合实体洋葱递归还原 + likely-clean 豁免 shape 门），真实流量出现率低，投入产出比低，归档后续候选。

50. **expr 容器可打印性门** ✅（P13 bench FP 归因）：post19 验证轮 strict-body 出现 1 条新 FP（74df46db，Ctrip 移动端 `saveLogInfo` 162KB 日志上报，body 为高熵乱码）——归因链跨三层：①插件 body 检测的 max_body_size（默认 64KB）门按 **chunk 粒度**截断，无负载时单次 IO 可读满 64KB，实际检测面达 130556 字节（3580+61440+65536 三次 IO 累计）；②检测面覆盖 64KB~130KB 区间的乱码段，其中 `${…}` 容器出现率≈1，`is_structural_expr` 的「identifier(」与运算符特征在乱码中同样≈1 命中 → strict 档 expr-injection critical → Block；③判决随 socket chunk 边界**抖动**——post18 bench 高负载下 chunk 碎片化、停点贴近 64KB 门，仅 TI-002/003 低分 Monitor → passed；post19 无负载大 chunk 一次越过门 → blocked。与 P13 needle 无关（needle 全注释仍复现）。修复：`is_structural_expr` 开头加容器内容**可打印性门**（全字节 `is_ascii_graphic()` 或空格）——真实 EL/SSTI/JSP payload 按构造全为可打印 ASCII（P2/P3 全部 EL/SSTI 正样本验证无损），乱码容器直接拒判结构。**双收益**：重跑后 74df46db 放行，且同族既有 FP 0db7f97（同族 Ctrip `SaveTraceInfo` 164KB 高熵 body，printable ratio 50%）一并从 post18 FP 集合消除——同一条 chunk 抖动链的两条误报一次修复带走，strict-body FP 22→21。方法论沉淀：**max_body_size 是 chunk 粒度近似而非硬上界**，任何「区间越过门才触达」的检测器都自带判决抖动，对乱码类高熵内容必须独立于长度门做质量过滤。

51. **URL fragment 盲区重定性（P14，零代码修复）** ✅：post18 REAL 面最后一项可修候选 ff/67（S2-045 OGNL 全量藏 URL `#` fragment 后）经三轮技术归因**从 REAL 漏报改判为链路伪影**：①`http` 1.5 `Uri` 无 fragment 存储位（scheme/authority/path_and_query 三元），探针实测 `#` 后内容被解析器静默丢弃（`/index.action?redirect:${#a=…}` → `path_and_query()` 仅返回 `"/index.action?redirect:${"`）；②pingora 0.9 `parse_request_target` 在构造 Uri **之前**按 RFC 9112 §3.2 主动剥离 fragment（源码注释 "must not reach the upstream request-line"），`raw_target` 保存的同样是剥后字节——插件层既拿不到内容也拿不到 `#` 存在信号；③pingwaf 转发上游的请求行不含 fragment，OGNL 载荷永远到不了 Struts2，**利用链在解析层物理断裂**。与「无 Content-Length POST」同级的部署形态伪影：样本库标黑基于直连服务器假设，反代形态下载荷无效。曾实现路径 B（`normalize_request` 加 `raw_fragment` 参数 + `ValueSource::Fragment` 变体 + plugin/server/triage 全消费侧接线）后确认解析层已丢弃而整体回滚。方法论沉淀：**跨层修复前先验证数据在源头是否可达**——一段 http::Uri 解析 probe 可省掉整轮接线；解析器的 RFC 合规剥离行为本身就是防护面的一部分。等效口径随之修正为 617/618 = 99.8%（伪影面 +1）。

### 收益矩阵（基于 bench 归因的保守估算）

| 方案 | 拦截率提升 | 误报影响 | 工作量 |
|---|---|---|---|
| P0-1 `+` 解码 | ✅ 已落地（sqli 70→85% 的组成部分） | 无（归一化等价） | 小时级 |
| P0-2 body 检测 | ✅ 已落地（+1.6pp Normal / +12.7pp Strict） | 已治理（+0.02pp Normal；Strict 1.98% 为档位设计） | 1 天内 |
| P0-3 needle 补齐 | ✅ 已落地（lfi +36pp、sqli +15pp） | 极低（sev5 均为强特征） | 小时级 |
| P1-4~10 | ✅ 已落地（Normal+body 38.1→44.1%，+6.0pp；crlf 0→40%、deser 0→33%） | **正向**（Normal 档 FP 0.23%→0.18% 全程最低；Strict 档 2.38% 为成员级检测的档位代价） | 2-3 天 |
| P2/P3-11~16（第三轮实测驱动） | ✅ 已落地（Normal+body 44.1→55.5%，+11.4pp；deser 33.3→100%、xss 33.3→40%、other 42.8→54.8%） | **正向**（回修后 Normal 档 FP 0.18%→0.13%；18 条 P1 遗留 FP 顺带消除；Strict+body 仅 2 条新增 FP） | 2-3 天 |
| P2-8/9/10 | 间接（支撑 FP <0.1% + 规则扩容） | **正向（FP 治理基建）** | 1-2 周 |

P0 全落地实测：Normal 36.5% / 0.21%，Normal+body 38.1% / 0.23%，Strict 51.1% / 0.35%，Strict+body 63.8% / 1.98%。P1 全落地实测：Normal 36.8% / 0.15%，Normal+body **44.1% / 0.18%**，Strict 51.4% / 0.35%，Strict+body 63.8% / 2.38%——主档（Normal+body）拦截 +6.0pp、误报同时下降，语义引擎（SQL 语句结构门、script-URI HTML 上下文门、字符串 JSON 再解包、CRLF 头名形态分源）首次实现拦截与误报同向改善。P2/P3 全落地实测（四轮迭代后）：Normal 46.8% / **0.10%**，Normal+body **55.5% / 0.13%**，Strict 63.8% / 0.32%，Strict+body **77.7% / 2.17%**——四配置零回退，三档零新增 FP；主档累计 +17.4pp（P0 38.1% 起），编码展开（b64 递归 + overlong UTF-8）+ 强正则扩面 + 形态分级把 strict+body 推到 77.7%（对齐 CRS PL3 上限水平）。strict 档剩余误报治理归 P3 label/count 灰度基建。

## 5. 明确不做

- 内嵌 ML 模型（SafeLine NLP/CF attack score）：样本内收益低于确定性组合信号，且引入模型分发/漂移维护成本；ScoreClass 分档结构已预留未来接入点。
- 全量正则换 Vectorscan：当前规模无收益，113 needle 的 AC 已在 GB/s 级；仅在规则面破千时启用（P3-20 预留）。
