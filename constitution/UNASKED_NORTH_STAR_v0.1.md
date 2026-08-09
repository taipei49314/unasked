# UNASKED — North Star Charter v0.1

> **工作代號：UNASKED**  
> **定位：Evidence-gated autonomous discrepancy discovery for engineered systems**  
> **標語：Find what nobody reported. Prove what actually happened. Stay silent when proof is insufficient.**

---

## 0. 專案級別

UNASKED 不是一般工具、聊天機器人、Code Review Agent，也不是「讓 AI 更主動」的功能展示。

它是一條需要長期維護定義、評測與證據權限的**旗艦研究主線**。它研究的不是模型會不會產生想法，而是：

> **機器能否在沒有人先告訴它問題是什麼之前，獨立找到一項值得知道的落差，並以可重播證據取得「發現」的宣告權。**

這個專案的第一優先不是功能數量，而是防止「AI 自己定義成功、自己產生證據、自己宣布已經會發現」。

---

## 1. 北極星

在一個受限、可觀察、可重播的工程世界中，系統不需要 Issue、錯誤訊息、失敗測試或問題位置提示，能夠：

1. 自行建立合理期待；
2. 找出期待與現實之間此前未被明確提出的落差；
3. 形成可證偽假設；
4. 設計並執行安全、最小、可重播的實驗；
5. 主動尋找反證，嘗試推翻自己的解釋；
6. 在乾淨環境中獨立重現；
7. 判斷其新穎性與決策影響；
8. 只有通過外部授權條件後，才允許稱為 Discovery；
9. 證據不足時，選擇保持沉默。

英文北極星：

> **Build a system that independently identifies a previously unstated, decision-relevant discrepancy; forms a falsifiable hypothesis; designs and executes an experiment; survives an active attempt to disprove itself; and earns the right to report the result through independently reproducible evidence.**

---

## 2. 核心論點

### 2.1 發現不是「產生一個有趣想法」

發現必須造成一項**有證據支持的信念更新**。模型生成的洞察、信心分數與漂亮報告都不是證據。

### 2.2 主動不等於自行傳訊息

真正的主動是：

- 沒有人先提供正確問題；
- 系統自己決定哪個落差值得追；
- 自己產生可證偽問題；
- 自己投入有限預算調查；
- 證據不夠時不打擾人。

### 2.3 第一階段的錯誤成本不對稱

早期目標不是最大化找到多少問題，而是：

> **錯過一項發現可以接受；錯把推測宣告成發現不可接受。**

因此優先順序是：可信度、可重播性、獨立性、精準度，最後才是召回率。

---

## 3. 第一個受限世界

終局可擴展到任何工程系統，但第一個世界固定為：

> **軟體 Repository Truth Discovery**

### 輸入

- 固定 commit 的 repository snapshot；
- 原始碼與設定；
- README、規格、Threat Model；
- Git 歷史；
- CI workflow 與可用執行紀錄；
- 測試、coverage 與 build metadata；
- release/tag/artifact metadata；
- Issues、Known Limitations 與 release notes 的封存快照。

### 系統收到的唯一高層任務

> Investigate this repository for material discrepancies. Do not assume that a discovery exists.

不得提供：

- 問題類型；
- 目標檔案；
- 錯誤訊息；
- 失敗測試；
- 已知漏洞位置；
- ground truth；
- 「你應該去看某個 workflow」之類方向提示。

### 輸出

零個或多個 Discovery Certificate。`NO_VERIFIED_DISCOVERY` 是完全合法且重要的輸出。

第一階段不自動修復問題，避免把「找到」與「改動後製造證據」混在一起。

---

## 4. Discovery 的正式定義

一項結果只有同時符合以下條件，才可進入 `VERIFIED`：

1. **Unasked**：候選問題不是由人類提示、Issue、失敗測試或 ground truth 洩漏而來。
2. **Previously unstated within a declared knowledge boundary**：在事先封存的 Issues、文件、release notes、已知問題與其他指定知識範圍內未被明確揭露。
3. **Discrepancy**：存在可指認的 Expectation 與 Observation 落差。
4. **Material**：成立後會改變 release、測試信任、安全判斷、功能支援、維護決策或其他事先定義的工程決策。
5. **Falsifiable**：存在可能使該假設被推翻的觀察或實驗結果。
6. **Evidence-backed**：結論連結到原始命令、輸出、artifact、hash、diff 或直接可驗證事實。
7. **Reproducible**：在乾淨環境、固定 snapshot 與明確步驟下可再次得到同一核心結果。
8. **Counterevidence-surviving**：系統已主動測試至少一項合理替代解釋或反例，且結論仍成立。
9. **Externally authorized**：提出候選的角色不能自行把它升級成 `VERIFIED`。

### 不算 Discovery 的結果

- 只有問題、想法、懷疑或風險清單；
- 已知 Issue 的改寫；
- 現有 failing test 的重述；
- lint、格式或純風格問題；
- 沒有展示實際後果的靜態 warning；
- 只因執行環境缺失造成的失敗；
- 由 prompt 明示方向後找到的結果；
- 模型自行撰寫 benchmark，再解出自己的 benchmark；
- 無法從乾淨環境重播的偶發結果；
- 模型的信心分數或文字解釋；
- 對全球首次發現的無根據宣稱。

「新穎」永遠相對於明確宣告的知識邊界；未經維護者或外部資料確認時，不宣稱全球未知。

---

## 5. Discovery 生命週期

```text
SIGNAL
  ↓
CANDIDATE
  ↓
HYPOTHESIZED
  ↓
TESTABLE
  ↓
SUPPORTED
  ↓
REPRODUCED
  ↓
VERIFIED
```

可在任一階段進入：

- `FALSIFIED`：假設被反證；
- `DUPLICATE`：在知識邊界內已知；
- `INCONCLUSIVE`：權限、資料或預算不足；
- `NON_MATERIAL`：真實但不改變工程決策；
- `ENVIRONMENTAL`：只屬於外部環境；
- `STALE`：snapshot 或條件已失效；
- `REVOKED`：後續證據推翻既有 verdict。

只有 `VERIFIED` 能被主動通知或作為公開發現宣稱。

---

## 6. 專案憲法

以下規則高於任何 Agent、模型、里程碑與產品需求：

### C-01 — Evidence before interpretation
模型摘要不能取代原始證據。

### C-02 — Separation of proposal and authority
提出候選、執行實驗與批准 verdict 必須分權；同一角色不得自行完成整條授權鏈。

### C-03 — Snapshot binding
每項 claim 必須綁定不可變的 repository commit、資料快照、policy 版本與工具版本。

### C-04 — Context provenance
必須記錄模型實際看到的檔案、提示、工具輸出與知識邊界，證明問題不是由提示洩漏。

### C-05 — Clean replay
所有 `VERIFIED` 發現必須能在無先前狀態的乾淨環境重播。

### C-06 — Counterevidence required
未嘗試合理替代解釋的候選不得升級為 `VERIFIED`。

### C-07 — Silence is valid
系統永遠不被要求「一定要找到東西」。

### C-08 — Hidden evaluation is sealed
被評測的 Explorer 不得讀取私有 ground truth、評分器或隱藏案例生成器。

### C-09 — No retroactive success criteria
評測開始後不得因結果不好而修改成功定義、severity 或評分規則；新規則只適用於下一個 protocol 版本。

### C-10 — Append-only history
失敗、反證、模型輸出與原始命令不得刪除，只能追加更正或撤銷紀錄。

### C-11 — Known is not discovered
已知問題即使被獨立重新找到，也只能標為 `REDISCOVERED` 或 `DUPLICATE`。

### C-12 — Confidence is not authority
模型自評 0.99 不增加任何 verdict 權限。

---

## 7. 權限模型

角色分離不等於一開始要做多 Agent swarm；早期可以由同一模型在不同隔離執行階段扮演不同角色，但權限、輸入與輸出必須分離。

| 角色 | 可以做 | 不可以做 |
|---|---|---|
| Principal Investigator | 定義範圍、憲法、隱藏評測、公開宣稱 | 在盲測開始後提示問題位置 |
| Explorer | 觀察、提出 candidate、建立 hypothesis | 設定 `VERIFIED`、讀取 hidden ground truth |
| Experiment Planner | 設計可證偽實驗、提出 capability request | 任意取得網路、秘密或宿主權限 |
| Sandbox Executor | 執行已允許命令、完整記錄結果 | 解釋結果、刪除失敗紀錄 |
| Falsifier | 尋找反例、替代解釋與不成立條件 | 偷改原始 candidate 或評分規則 |
| Independent Reproducer | 在乾淨環境重播 | 使用 Explorer 的未記錄狀態 |
| Discovery Authority Kernel | 依 deterministic policy 檢查升級條件 | 以模型直覺補足缺少的證據 |
| Human Judge（早期） | 最終 public claim 與 materiality 裁決 | 修改既有 run 的 protocol 使其通過 |

### Capability 原則

最小權限集合：

- `OBSERVE`
- `PROPOSE_CANDIDATE`
- `REQUEST_EXPERIMENT`
- `EXECUTE_SANDBOX`
- `SUBMIT_EVIDENCE`
- `CHALLENGE`
- `REPLAY`
- `AUTHORIZE_VERDICT`
- `PUBLISH`

Explorer 永遠沒有 `AUTHORIZE_VERDICT` 或 `PUBLISH`。

---

## 8. 系統架構

```text
Immutable Target Snapshot
        ↓
Observation Plane
        ↓
World / Evidence Ledger
        ↓
Expectation Graph
        ↓
Candidate Search
        ↓
Hypothesis Registry
        ↓
Experiment Planner
        ↓
Capability-Gated Sandbox
        ↓
Counterevidence / Falsification
        ↓
Independent Clean Replay
        ↓
Novelty + Materiality Review
        ↓
Discovery Authority Kernel
        ↓
REPORT / ARCHIVE / REJECT
```

### 8.1 Immutable Target Snapshot

固定：

- commit SHA；
- submodule 狀態；
- dependency lock；
- CI metadata snapshot；
- Issue/文件/known issue snapshot；
- protocol 與工具版本。

任何後續變更都建立新 run，不覆蓋舊 run。

### 8.2 Observation Plane

收集可追溯事實，不先做結論：

- 宣稱與規格；
- 程式結構與可達入口；
- workflow trigger、job、condition；
- test-to-code path；
- build/release artifact；
- 歷史變化與 baseline；
- runtime 或 CLI 行為；
- skip、suppression、continue-on-error；
- 版本與內容 hash。

每個 observation 都必須有來源、擷取方式、時間、snapshot 與完整性狀態。

### 8.3 Expectation Graph

期待來源分三類：

- **Explicit**：README、規格、宣稱、支援矩陣；
- **Structural**：由控制流、入口、測試與安全邊界推導；
- **Historical**：由過去 release、執行時間、artifact 數量、coverage 與行為建立 baseline。

模型可以提出 expectation，但必須附來源與推理鏈；沒有來源的期待只能是弱候選，不能直接支撐 `VERIFIED`。

### 8.4 Candidate Search

兩條路徑並行：

1. deterministic detectors：找穩定、便宜、可解釋的可疑區域；
2. model explorer：跨來源產生此前未被明示的問題與替代解釋。

兩者必須獨立評測，以確認模型是否超越規則掃描器，而不是只是換一種報告語言。

### 8.5 Hypothesis Registry

每個 candidate 至少包含：

- 主假設；
- 至少一個無害解釋；
- 可推翻條件；
- 最小實驗；
- 預期觀察；
- 成本與風險；
- 所需 capability。

不得只保留最戲劇化的單一解釋。

### 8.6 Experiment Planner

將假設轉成可重播計畫：

- 使用隔離 worktree；
- 優先最小反例；
- 變更僅存在於 sandbox；
- 每個命令有目的與預期；
- 預先聲明成功、失敗與不確定結果；
- 不允許看完結果後重寫判定條件。

### 8.7 Capability-Gated Sandbox

第一版建議：本機或 WSL2 中的容器化 adapter。

要求：

- 預設無網路；
- command allowlist；
- CPU、時間、磁碟與程序限制；
- secret-free 環境；
- 只寫隔離 worktree；
- stdout、stderr、exit code、diff、artifact hash 全記錄；
- 可產生單一 `reproduce.sh` 或等價重播入口。

### 8.8 Counterevidence / Falsification

Falsifier 必須至少嘗試：

- 一個合理替代解釋；
- 一個負對照；
- 一個語義等價變形或不同環境條件；
- 一項可能證明 observation 不完整的查核。

反證成功是有價值的研究結果，不視為施工失敗。

### 8.9 Independent Clean Replay

Reproducer 只取得：

- target snapshot；
- Discovery Certificate；
- 重播腳本；
- 明確依賴。

不取得 Explorer 的隱藏暫存、人工提示或未記錄檔案。

### 8.10 Discovery Authority Kernel

以 deterministic policy 檢查：

- 狀態轉移是否合法；
- 必要 artifact 是否存在；
- hash 是否一致；
- clean replay 是否通過；
- counterevidence 是否完成；
- known-issue scan 是否完成；
- protocol 是否在 run 前凍結；
- 提出者是否試圖自行授權。

它不判斷世界真相，只判斷「目前證據是否有權支持這種語意」。

---

## 9. Discovery Certificate 與證據包

```text
discoveries/D-000017/
├── certificate.yaml
├── target.json
├── protocol.json
├── context-manifest.json
├── blindness-attestation.json
├── observations.jsonl
├── expectations.jsonl
├── hypotheses.yaml
├── experiment/
│   ├── plan.yaml
│   ├── commands.jsonl
│   └── reproduce.sh
├── evidence/
│   ├── stdout/
│   ├── stderr/
│   ├── diffs/
│   ├── artifacts/
│   └── hashes.json
├── counterevidence/
├── replay/
│   ├── environment.json
│   ├── commands.jsonl
│   └── result.json
├── novelty.json
├── materiality.json
├── limitations.md
└── verdict.json
```

### Certificate 必填內容

- 這項發現改變了什麼信念；
- Expectation 的來源；
- Observation 的直接證據；
- 主假設與替代解釋；
- 可證偽條件；
- 實驗與結果；
- 反證嘗試；
- clean replay；
- 已知問題查核的知識邊界；
- 決策影響；
- 限制與尚未確認部分；
- verdict、授權者與 policy hash。

所有大型 artifact 使用 content-addressed storage；Certificate 只引用 hash，不依賴模型摘要。

---

## 10. 評測系統：Unasked Trials

不要使用已被廣泛使用的通用名稱作為正式品牌；本文件以 **Unasked Trials** 代稱評測體系。

### 10.1 四層評測

1. **Public Development Set**：公開範例，只用於格式、工具與基本能力開發。
2. **Sealed Evaluation Set**：私有、預先封存、Explorer 無法存取的隱藏案例。
3. **Negative Controls**：乾淨 repository、合理例外與誘餌異常，專門測 false discovery。
4. **Wild Trials**：真實開源 repository 的預註冊調查；結果需維護者或獨立專家確認。

另建立 **Metamorphic Variant Generator**：對命名、路徑、語言、workflow 結構與無關內容做變形，測試系統是否只記住 fixture 指紋。

### 10.2 第一批 discrepancy 類別

- claim-to-execution mismatch；
- declared capability but unreachable path；
- tests pass but claimed behavior is not exercised；
- source/tag/artifact divergence；
- failure suppression or green-by-skipping；
- security/control bypass under semantics-preserving transformation；
- claimed determinism with nondeterministic output；
- repair that closes one case while violating another invariant。

### 10.3 Ground Truth 格式

每題在評測前封存：

- hidden discrepancy；
- materiality class；
- minimum acceptable evidence；
- disallowed shortcuts；
- known false-positive traps；
- valid counterevidence；
- clean reproduction procedure；
- knowledge boundary；
- hash 與封存時間。

被測模型不得參與建立該輪 hidden ground truth。

### 10.4 基準與消融

至少比較：

- deterministic detectors only；
- read-only LLM reviewer；
- LLM + tools, no experiment gate；
- experiment loop without falsifier；
- full evidence-gated system。

要回答的不是「完整系統能不能找到東西」，而是每個新增元件是否真的提高可信發現產率。

---

## 11. 北極星指標

### Trusted Unasked Discovery Yield（TUDY）

```text
TUDY = Σ ImpactWeight(VERIFIED ∩ UNASKED ∩ NOVEL) / Normalized Investigation Budget
```

只有同時通過 unasked、novelty boundary、clean replay、counterevidence 與 external authority 的發現才計分。

### 硬性護欄

- **False VERIFIED Claim Rate：0**；
- 所有公開 `VERIFIED` 均須有 replay bundle；
- 連續主動模式開放前，Interruption Precision 必須達到預註冊門檻；
- 評測政策變更不得追溯套用。

### 次要指標

- Candidate Precision；
- Hidden Discovery Recall；
- Independent Discovery Rate；
- Clean Reproduction Rate；
- Counterevidence Rejection Yield；
- Decision Impact Rate；
- Interruption Precision；
- Duplicate Alert Rate；
- Cost per Verified Discovery；
- Time to First Falsifiable Hypothesis；
- Evidence Completeness；
- Human Steering Count。

第一階段優先看 precision、reproduction 與 evidence completeness，不追求高 recall。

---

## 12. 里程碑

里程碑以「證明什麼」定義，不以日期或功能數量定義。

### P0 — Constitution Freeze

**要證明：** 我們能先固定何謂發現、何謂作弊、何謂證據。

交付：

- North Star Charter；
- Discovery Definition；
- Authority Model；
- Threat Model；
- artifact schemas；
- work-package template；
- private benchmark custody protocol。

退出條件：

- 一個人工建立的 positive certificate 可完整驗證；
- 一個 clean control 正確輸出 `NO_VERIFIED_DISCOVERY`；
- protocol hash 能被 run 綁定。

此階段禁止宣稱系統具備 discovery 能力。

### M0 — Blind Proof

**要證明：** 在無問題提示下，系統能找到至少一項真實、可重播的隱藏落差。

限制：

- 單一 repository；
- 單次 bounded investigation；
- 一個 Explorer 模型；
- 無網路；
- 無 UI；
- 無自動修復；
- hidden cases 在 Explorer 開發前封存。

演示門檻：

- 至少 1 項 hidden discrepancy 進入 `VERIFIED`；
- clean replay 成功；
- 無人工方向提示。

M0 正式退出門檻：

- 5 個 hidden positive cases 至少通過 3 個；
- 2 個 clean/decoy controls 零個錯誤 `VERIFIED`；
- 所有 `VERIFIED` 100% clean replay；
- context provenance 完整；
- 沒有修改評分政策、hidden data 或 target 原始 snapshot。

### M1 — Repeatability Across Repositories

**要證明：** 成功不是單一 fixture 偶然或命名記憶。

範圍：

- 至少 5 個 repository；
- 至少 20 個未見變體；
- 至少 4 類 discrepancy；
- 包含 metamorphic variants 與 clean controls。

退出條件：

- False VERIFIED Claim Rate 仍為 0；
- 人工接受的 candidate precision 達預註冊門檻；
- clean reproduction 達預註冊門檻；
- impact-weighted yield 超過 deterministic-only 與 read-only LLM baseline；
- 沒有為 hidden fixture 寫專屬規則。

### M2 — Autonomous Experiment Design

**要證明：** 系統不只是高級靜態掃描器。

退出條件：

- 至少 5 項 `VERIFIED` discovery 必須依賴系統自行生成的新測試、輸入變形、狀態操作或最小反例；
- 這些結果不能由既有 detector 直接得出；
- 每項實驗都有事前成功/失敗條件與 clean replay。

### M3 — Self-Falsification

**要證明：** 系統會主動降低自己的錯誤信念，而不是只累積支持證據。

退出條件：

- Falsifier 能穩定推翻一部分原本看似合理的 candidate；
- 相較沒有 Falsifier 的消融版本，錯誤升級顯著下降；
- verified yield 不因過度保守而完全崩潰；
- 被推翻的假設保留完整紀錄。

### M4 — Longitudinal Discovery

**要證明：** 系統能持續觀察變化，而不是只做一次掃描。

新增能力：

- commit-to-commit delta；
- discovery staleness；
- resolved/reintroduced detection；
- duplicate suppression；
- investigation budget scheduler；
- interruption policy。

退出條件：

- Interruption Precision 達預註冊門檻；
- duplicate alert rate 在門檻內；
- 能正確撤銷 stale discovery；
- 無 `VERIFIED` 時保持沉默。

### M5 — Cross-Source Discovery

**要證明：** 系統能發現單一來源看不到的矛盾。

至少涵蓋：

- code；
- docs/spec；
- CI history；
- release/artifacts；
- Issues/known limitations；
- 可控 runtime observation。

退出條件：

- 至少一項高影響 discovery 必須依賴三個以上來源的聯合證據；
- 維護者或獨立評審確認其確實改變工程決策。

### M6 — Engineered Systems Beyond Repositories

只有在 M5 通過後，才研究資料管線、模型評測、企業流程、硬體驗證或其他工程世界。

不直接跳到「自主科學家」。

---

## 13. 強制範圍鎖

在對應里程碑前禁止：

- M2 前做 dashboard；
- 單模型 baseline 成立前做 swarm；
- M3 前做持續主動通知；
- M4 前做自動修復；
- M1 前直接整合 Greenwash 或 ClaimGate 程式碼；
- 沒有量測證據前加入 vector database、長期記憶或複雜知識圖譜；
- M5 前宣稱通用 autonomous discovery；
- hidden benchmark 未通過前使用「AI 已學會主動發現」作為宣傳語。

每次想增加元件，都必須回答：

> 它會提高哪一個已定義指標？若拿掉它，哪項能力會失效？

無法回答就不加入。

---

## 14. 與既有專案的關係

三者可以形成概念上的 Evidence Authority Stack，但早期保持程式碼獨立。

### UNASKED

> 找出沒有人提出、值得被驗證的候選落差。

### Greenwash

> 分析既有宣稱與證據是否一致。

### ClaimGate

> 決定現有證據有沒有權支持某種結論或完成宣告。

概念閉環：

```text
UNASKED finds the candidate gap
        ↓
Greenwash audits claims against reality
        ↓
ClaimGate authorizes what the evidence is allowed to mean
```

整合原則：

1. M0 只借用哲學，不借用程式碼；
2. M1 後才以穩定 JSON Schema 互通；
3. 每個專案仍可獨立執行與評測；
4. 不允許三個專案互相引用彼此的宣稱作為證據；
5. dogfood 結果必須由外部 replay 驗證。

---

## 15. 主要威脅模型

| 威脅 | 典型表現 | 防線 |
|---|---|---|
| Benchmark leakage | Explorer 看見答案、fixture 名稱或評分器 | private repo、sealed hash、權限隔離 |
| Prompt hint leakage | 人類不小心指向問題位置 | context manifest、盲測後禁止 steering |
| Fixture overfitting | 只認得檔名與固定結構 | metamorphic variants、跨語言與重新命名 |
| Claim laundering | 把「可能」改寫成「已發現」 | deterministic state machine、authority separation |
| Evidence fabrication | 宣稱跑過未執行命令 | executor-generated logs、hash、exit code |
| Cherry-picking | 只保留成功輸出 | append-only event ledger、完整 run archive |
| Novelty inflation | 已知 Issue 被包裝成新發現 | frozen knowledge boundary、duplicate scan |
| Impact inflation | 小異常被稱為高風險 | predeclared impact classes、human/materiality review |
| Environment artifact | 缺 dependency 被誤判為 product bug | clean controls、environmental verdict |
| Policy mutation | 看完結果後改成功條件 | protocol hash、non-retroactivity |
| Hidden human help | 人類中途提示 | steering count、run lock、完整 transcript |
| Budget gaming | 無限探索直到碰巧撞中 | bounded calls/time/compute、normalized cost |
| Self-authored test bias | Agent 寫只會證明自己的測試 | negative controls、independent replay、falsifier |
| Stale discovery | target 已修復仍持續警報 | snapshot binding、staleness checks |

---

## 16. 治理與施工權限

### Principal Investigator（你）

- 北極星與範圍最終所有者；
- hidden benchmark custodian；
- Constitution 與 Claims Policy 的 CODEOWNER；
- 公開發現的最終核准者；
- 盲測開始後不得提供方向提示。

### Research Architect / Adversarial Reviewer

- 把直覺形式化；
- 拆解 research question；
- 設計反例、消融與 threat model；
- 審查是否偷改成功定義；
- 不持有 hidden ground truth 的實作權限。

### Builder Agents

只接封閉工作包：parser、ledger、sandbox、schema、CLI、detector、replay、測試與局部重構。

不得獲得：

- 修改 `constitution/`；
- 修改該輪 evaluation policy；
- 讀取 private benchmark；
- 自行宣稱系統已具備 discovery 能力；
- 在沒有 evidence bundle 時標記完成。

### Red-Team Agent

專門攻擊：

- benchmark 可作弊性；
- evidence gate 繞過；
- claim/state escalation；
- hidden human steering；
- false novelty；
- clean repo 誤報。

Red-Team 找到繞過不代表核心能力完成，只代表防線需要修正。

---

## 17. 工作包格式

每個 Agent 任務必須包含：

```text
Work Package ID:
Objective:
Research question supported:
Allowed paths:
Forbidden paths:
Inputs:
Required outputs:
Acceptance tests:
Required raw evidence:
Failure states:
Out-of-scope:
Forbidden claims:
Rollback procedure:
```

範例：

```text
Objective:
實作 GitHub Actions workflow 靜態觀察器。

Allowed paths:
src/unasked/observers/github_actions/
tests/observers/github_actions/

Forbidden paths:
constitution/
policies/
bench-private/

Acceptance:
指定 fixture 產生 deterministic observation.json；
輸出包含 workflow path、trigger、job condition 與來源 hash。

Forbidden claims:
不得宣稱系統已能發現 workflow 問題；
不得把 observer output 標為 Discovery。
```

---

## 18. 建置順序

### Commit 0 — Freeze the constitution

建立：

- `NORTH_STAR.md`
- `DISCOVERY_DEFINITION.md`
- `AUTHORITY_MODEL.md`
- `CLAIMS_POLICY.md`
- `THREAT_MODEL.md`

### Commit 1 — Seal the first hidden evaluation

在獨立私有儲存庫建立：

- 5 個 positive cases；
- 2 個 clean/decoy controls；
- ground-truth manifests；
- sealed hashes。

這一步必須在 Explorer loop 開發前完成。

### Commit 2 — Artifact schemas

建立：

- run；
- observation；
- expectation；
- hypothesis；
- experiment；
- evidence；
- replay；
- verdict；
- discovery certificate schemas。

### Commit 3 — Append-only event ledger

每個 run 記錄：

- target；
- protocol hash；
- model/provider；
- tool list；
- context manifest；
- command logs；
- state transitions；
- human interventions。

### Commit 4 — Snapshot and observation layer

只建立事實，不做 discovery claim。

### Commit 5 — Capability-gated sandbox and replay

先證明命令可完整記錄與乾淨重播。

### Commit 6 — Deterministic baselines

建立最小 detector，作為模型增益的比較基準。

### Commit 7 — Explorer and hypothesis protocol

一個模型、有限工具、有限預算；先不做 swarm。

### Commit 8 — Falsifier and authority kernel

先確保錯誤 candidate 無法自行升級。

### Commit 9 — M0 blind run

評測規則在 run 前凍結；完整保存失敗與成功結果。

---

## 19. 第一版技術邊界

建議技術選擇：

- Python CLI；
- Pydantic / JSON Schema；
- JSONL append-only event log；
- SQLite 作索引，不作真相來源；
- content-addressed artifact store；
- Git worktree；
- Docker/WSL2 sandbox adapter；
- 單一模型 provider abstraction；
- Markdown + JSON 報告；
- 無 Web UI；
- 無向量資料庫；
- 無多 Agent orchestration；
- 無自動 PR 或修復。

建議 CLI：

```bash
unasked init ./repo --commit <sha>
unasked observe --run <id>
unasked investigate --run <id> --budget <policy>
unasked challenge D-000017
unasked replay D-000017 --clean
unasked verify D-000017 --policy <hash>
unasked report --verified-only
```

---

## 20. Claims Policy

### P0 / v0.0.x 允許宣稱

> A research harness for blind, evidence-gated repository investigation.

禁止宣稱：

- autonomous discovery agent；
- finds unknown bugs；
- self-driving researcher；
- validated proactive intelligence。

### M0 通過後允許宣稱

> Demonstrated blind discovery of reproducible discrepancies on a sealed evaluation set.

必須同時公開：

- protocol；
- aggregate results；
- false-positive controls；
- evidence/replay format；
- 已知限制。

### M2 通過後允許宣稱

> Demonstrated autonomous experiment design for selected repository discrepancy classes.

### M4 通過後才可宣稱

> Continuous proactive repository discovery with measured interruption precision.

任何宣稱都綁定特定版本、benchmark 與 knowledge boundary，不宣稱通用智能。

---

## 21. Go / No-Go 規則

### 繼續投入的條件

- M0 能在盲測中交出至少一項真正可重播 discovery；
- M1 完整系統在 impact-weighted yield 上超越 deterministic baseline；
- Falsifier 與 authority separation 確實降低錯誤升級；
- 人類審查能從 evidence bundle 獨立得出相同結論。

### 停止擴張、回到研究的條件

- 需要人類提示才能穩定找到問題；
- 模型只會重述 detector 結果；
- clean controls 經常被誤報；
- replay 依賴未記錄狀態；
- benchmark 只能靠 fixture 專屬規則通過；
- 工程量持續增加，但 TUDY 沒提高；
- dashboard、swarm 或記憶系統開始掩蓋核心能力未被證明。

若模型未超越 baseline，專案仍可留下有價值的 benchmark、evidence protocol 與 authority kernel，但不得改寫成成功的 autonomous discovery 故事。

---

## 22. 最終形態

成熟的 UNASKED 不應每天產生大量「洞察」。它應該像一個安靜的研究員：

- 長時間觀察；
- 主動形成問題；
- 用有限資源做決定性實驗；
- 對自己的結論保持敵意；
- 保留完整證據與失敗歷史；
- 知道何時沒有足夠證據；
- 只有在一項結果真的值得改變人類決策時才出聲。

最終成功不是「AI 變得很會講」。

最終成功是：

> **某一天，它在沒有人問對問題之前，找到了一項人類尚未明確知道的真實落差；我們能從乾淨環境重播它、推翻其他解釋，並因為這項發現改變原本的工程決策。**

那一刻，UNASKED 才真正跨過「回答」與「發現」之間的界線。
