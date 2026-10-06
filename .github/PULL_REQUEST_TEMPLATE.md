<!--
PingWAF pull request template. Fill in every section; delete the guidance
comments but keep the headings. For the checklist, replace [ ] with [x].
-->

## 变更说明 / Description

<!-- What does this PR do and why? Link design notes or screenshots for UI work. -->

## 关联 Issue / Linked Issue

<!-- e.g. Fixes #123, Closes #456. Leave "N/A" if there is none. -->

Fixes #

## 变更类型 / Type of Change

- [ ] 🐛 Bug fix — 非破坏性问题修复 / non-breaking fix
- [ ] ✨ New feature — 新特性（请先开 Issue 讨论 / discuss in an issue first）
- [ ] 🛠️ Refactor / performance — 重构或性能优化，不改变外部行为
- [ ] 🔒 Security — 安全相关修复（参见 SECURITY.md）
- [ ] 📝 Docs / i18n — 文档或多语言更新
- [ ] ⚙️ CI / build / deps — 构建、流水线或依赖变更

## 检查清单 / Checklist

- [ ] `cargo fmt --all` 已运行 / formatting applied
- [ ] `cargo clippy --all-targets --features full -- -D warnings` 无告警 / no warnings
- [ ] `cargo test --workspace --features full` 通过 / tests pass
- [ ] `cd web && npm run lint && npm run build` 通过（若改动前端）/ web lint + build pass if the frontend changed
- [ ] 已更新相关文档 / docs updated where behaviour changed
- [ ] 已阅读并同意 [贡献者许可协议 / CLA](../blob/main/CLA.md)
