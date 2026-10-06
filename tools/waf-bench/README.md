# waf-bench

WAF 拦截效果基准测试：用 [chaitin/blazehttp](https://github.com/chaitin/blazehttp)
的开源攻击样本（标准原始 HTTP 报文，`.black` 预期拦截 / `.white` 预期放行）回放
PingWAF 数据面，量化默认规则的真实拦截率与误报率。

## 组成

| 文件 | 用途 |
| --- | --- |
| `replay.py` | 样本回放器：raw socket 逐字节发送（保真畸形样本），逐样本判定与攻击类别归因，输出 JSONL |
| `summarize.py` | 汇总 JSONL：总体指标（双口径）、类别交叉表、漏报/误报样本清单（markdown） |
| `mock_origin.py` | echo 上游：所有方法/路径一律 200，保证非 200/503 响应只可能来自 WAF 或协议层 |
| `conf/*.toml` | 静态模式（`pingwaf -c`）矩阵配置，监听 `127.0.0.1:6188`，上游 `127.0.0.1:6199` |

## 判定口径

| verdict | 含义 |
| --- | --- |
| `blocked` | 403（block 页）/ 503（challenge 页）——WAF 判决 |
| `passed` | 2xx/3xx——到达上游 |
| `protocol_reject` | 400/413/414/431/501——pingora 协议层拒收（如请求行含裸空格/`<`），非 WAF 判决 |
| `rate_limited` | 429 |
| `error` | 超时 / 连接重置 |

报告使用两个口径：**strict**（只算 `blocked`）与 **wide**（`blocked` +
`protocol_reject` + `error`，用于与官方 blazehttp 二进制对账——官方客户端无法区分协议层拒绝）。

## 运行

```bash
# 样本（一次性）
git clone --depth 1 https://github.com/chaitin/blazehttp /tmp/blazehttp

# 1. 起上游
python3 tools/waf-bench/mock_origin.py --port 6199 &

# 2. 起数据面（每组一份配置，改配置需重启进程）
./target/debug/pingwaf -c tools/waf-bench/conf/g1-block-default.toml &

# 3. 烟测
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:6188/                                # 200
curl -s -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:6188/?id=1%20union%20select%201'    # 403
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:6188/.env                            # 403

# 4. 全量回放
python3 tools/waf-bench/replay.py /tmp/blazehttp/testcases \
  -t 127.0.0.1:6188 -g g1 -o /tmp/waf-bench/g1.jsonl

# 5. 汇总
python3 tools/waf-bench/summarize.py /tmp/waf-bench/*.jsonl > /tmp/waf-bench/summary.md
```

### replay.py 参数

| 参数 | 说明 |
| --- | --- |
| `-t` | 目标 `host:port` |
| `-g` | 组标签（写入 JSONL，用于汇总分组） |
| `-o` | 输出 JSONL 路径 |
| `--concurrency` / `--delay-ms` | 并发线程数（默认 8）与请求间隔（默认 10ms） |
| `--xff` | 逐样本轮换 `X-Forwarded-For`。agent 模式必开：数据面会把 Block 判决的来源 IP 自动封禁 600s，同源回放会被污染；同时也让 `/admin` 质询规则（PINGWAF-1001，排除内网段）按公网语义生效 |
| `--xff-base` / `--xff-count` | 轮换池起点（默认 `203.0.113.1`）与大小（默认 254）。**注意**：混跑黑白样本时池必须远大于"样本数 / 期望封禁窗口"的比值，否则黑样本封禁后同 IP 白样本被边缘连带拒绝，表观误报率虚高（实测 254 池 33877 样本混跑误报 26.4%，黑/白分离纯净复测后 1.27%）。纯净复测建议：黑白样本分目录回放 + `--xff-base 10.254.0.1 --xff-count 65534` |
| `--host-rewrite` | 统一覆写 Host 头。agent 模式按 Host 精确匹配站点规则，样本 Host 各异，需统一成站点域名 |
| `--limit` | 只回放前 N 个样本（冒烟用） |

### agent 离线模式（复刻控制面默认规则集）

静态 TOML 模式只加载引擎托管规则，控制面播种的站点默认规则需用 agent 离线模式：

1. 用临时脚本构造 `cache/sites.json`（规则表达式逐字取自
   `pingwaf-server/src/defaults.rs`；站点 PL 由控制面按
   `max(规则 severity)` 推导 = 4，站点 `mode = block`）。
2. `./target/debug/pingwaf agent --server-url http://127.0.0.1:1 --cache-dir <dir> --fail-open`
   ——数据面凭磁盘缓存启动（无证书时只绑 80 端口），gRPC 断连重试噪音可忽略。
3. 回放加 `--xff --host-rewrite <站点域名>`。

规则表达式经 `CompiledRule::compile` 编译失败会被**静默丢弃**，启动后先用探针
（SQLi / `.git` / TRACE / 扫描器 UA 各一条）确认 11 条规则实际生效。

纯净指标复测（消除 auto-block 连带）：黑样本与白样本分目录（symlink 即可）分别回放，
每样本独享轮换 IP：

```bash
mkdir -p /tmp/waf-bench/only-black /tmp/waf-bench/only-white
find /tmp/blazehttp/testcases -name '*.black' -exec ln -s {} /tmp/waf-bench/only-black/ \;
find /tmp/blazehttp/testcases -name '*.white' -exec ln -s {} /tmp/waf-bench/only-white/ \;
python3 tools/waf-bench/replay.py /tmp/waf-bench/only-black \
  -t 127.0.0.1:80 -g g4-black -o /tmp/waf-bench/g4-black.jsonl \
  --xff --xff-base 10.254.0.1 --xff-count 65534 --host-rewrite <站点域名>
# 白样本同上，only-white / g4-white
```

## 矩阵

| 组 | 配置 | 检验点 |
| --- | --- | --- |
| G1 | block / PL2 / threshold 40 | 静态托管规则主基线 |
| G2 | monitor / PL2 / threshold 40 | 出厂默认监控模式（预期拦截率 0%） |
| G3-pl1 / pl3 | PL 1 / 3 | 灵敏度曲线（PL3 激活空-UA 质询与超长 URI 规则） |
| G3-th30 / th60 | threshold 30 / 60 | 聚合阈值敏感性 |
| G4 | agent 离线复刻控制面默认 11 条 + PL4 | 产品默认规则集 + auto-block 行为 |
| level-normal / level-strict | block / PL2 / threshold 40 / `level` 二档 | 拦截级别对比（报告 §9）：Strict 装配 strict-only 签名、收紧托管阈值并激活 PL3；插件段可配 `stacks` 按后端技术栈收窄签名加载 |
| spot-monitor-sqli / spot-monitor-java | block / PL2 / `monitor_categories = ["sqli"]` 或 `monitor_stacks = ["java"]` | 分类监听降级：命中名单的检测转 Monitor，其余照常 Block |
| spot-advanced | block / PL2 / `advanced_mode = true` | 站点级高级模式 = Strict 级别 + body 深度检测（对照 level-strict-body） |
