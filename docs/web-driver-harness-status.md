# K275 driver harness: 静的検証の現在地

本資料は2026-11-18 02:41 UTCまでに確定した限定成果を記す。R3は未実行のソース候補であり、Goのcompile/gofmt・SQLite実行・認可runtimeの受入れではない。K275全体とLG01–LG09の本番条件は未解決である。

## 既存の統合と今回の変更

- [PR #110](https://github.com/g-kari/devsecops-console/pull/110)は2026-11-17 16:22:12 UTCにmain dc181ba0a41c4c0c6f739fe40b3c29c9a9bec23aへ通常統合済み。同SHAの[Check](https://github.com/g-kari/devsecops-console/actions/runs/44124977845)と[Trial](https://github.com/g-kari/devsecops-console/actions/runs/44124977882)は初回成功。これらは既存資料変更のCIで、以下のR3を実行した結果ではない。
- LG02–04の排他・不明時停止・readback境界を検討するため、製品コードから独立した合成driver harnessを準備した。R3はその静的補正であり、このPRにharness本体や実行入口は追加しない。
- case終了時に後から観測したtimeout/cancelが、それより前に返ったSQL・rollback・readbackの診断を上書きする欠陥を修正した。先行Detailを保持し、後発事象はCaseContextErrorへ分離する。ClassificationとCallerOutcomeをunknownへ落とす規則は維持する。
- 独立静的レビューはsource-onlyで受入れ。SQL、transaction、fixture、retry、時間上限、NO_GO入口は変更していない。逆向きの2置換で元R2全文と一致する。

R3固定ソースは14,452 bytes、SHA256 33de3507a076f00204ce648d43a3df4e1cfa7ca9dc1dbeee28604a173dc81b0d。固定hashは資料の識別であり、それ自体が実行結果や安全性の証明ではない。検証担当の保存成果物に対応するが、実行可能ソースをこの公開資料から配布するものではない。

## 実行した検証と実行していない検証

| 区分 | 結果 | 限界 |
| --- | --- | --- |
| metadata/hash/textの静的検査 | 正例と73否定を独立再実行し、保存出力bytes一致 | Go parser、型検査、compiler、SQL検査ではない |
| Pythonの結果フィールド保持モデル | 12組を確認。4つの改変種別を8つのcontext条件で拒否（32条件） | Goを実行・翻訳したものではなく、実際のraceを再現していない |
| R2→R3の差分 | 新しい診断欄とcase-context処理だけ。module/acceptanceは不変 | 独立静的レビューの限定受入れ |
| Go compile/gofmt・driver/SQL・D01–D03 | 未実行 | runnerと依存物の前提が未成立 |
| 元の37＋42＝79認可negative/crash行 | 未実行 | 上の73/12/32と対象が違い、代替・合算しない |
| 実IdP・実token・ログイン/session・作用先 | 未実装／未検証 | allowやSessionSnapshotを生成する根拠にしない |

## 合成driver検証の予定範囲

- D01: 固定9フィールドのrecordを条件付き更新し、exact before/afterを束縛するreceiptと同一transactionでcommit。その後の新しいread snapshotを照合する。
- D02: tentative update後にreceipt主キー重複を意図的に発生させ、対象caseのrollbackとprestate保持を観測する。全ての失敗でrollbackが保証されるとは一般化しない。
- D03: prospective testでoracleが成功commitを観測しても、論理的なcaller ackを渡さずcallerはunknownを維持する。readbackは歴史的証拠だけで、再送・再commit・許可を与えない。実際の電源断、I/O fault、network lossの試験ではない。

これら3件はまだ実行していない。単一の合成DB sliceが将来合格しても、全writer排他、owner交代、DB巻戻し・複製・ABA、耐久性、全入口停止、外部作用との原子性の証明にはならない。

## 実行へ進む条件

1. 既存データ・資格情報・他担当領域を持ち込まない、独立に所有・隔離されたrunnerを確保する。
2. 完全なGo 1.27.4 toolchain、module corpusと選択されたbuild graphを認証する。sqlite 1.62.0 / libc 1.80.1 / x/sys 0.50.0は候補の固定値であり、取得・検証済みとはしない。
3. 実行時の無通信と、外部から強制するwall/CPU/memory/storage/output上限を検証する。contextや事後ファイルサイズ観測だけでは強制上限にならない。build時の予算は別に決める。
4. 入口の有効化とprovenance/output保持を別レビューし、その後にcompile/formatとD01–D03を行う。
5. 制限・unknown・予想外の結果が出たら停止し、勝手に上限を上げたり再送・再実行しない。

現在は実行環境未成立。隔離準備の限定probeも権限制限で停止しており、ネットワーク共有への変更や権限昇格で迂回しない。mainのNO_GO表示だけを安全な実行許可とはしない（import初期化はmainより先に起こり得る）。

## 公開状態と境界

この変更は公開資料・ロードマップの同期のみ。製品コード、CI guard、認証・権限、DB、provider/client登録、Site本体は変更しない。公開JSONの配信確認とSite実画面の受入れは別であり、実画面は未検証のまま。各工程の過去観測時刻を保持し、全33工程を今回再検証したとは扱わない。

[current-statusの既存設計](./web-current-status-design.md)にある実装NO_GOと失効・状態・local認可の独立境界を維持する。
