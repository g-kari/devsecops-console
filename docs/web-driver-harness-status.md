# K275 driver harness: 静的検証の現在地

本資料はR3静的成果（2026-11-18 02:41 UTC）と、後段に記す依存宣言・隔離前提の限定検証を時点別に記す。後段のIntel Mac CI対象変更は、それとは別の検証範囲変更である。R3は未実行のソース候補であり、Goのcompile/gofmt・SQLite実行・認可runtimeの受入れではない。K275全体とLG01–LG09の本番条件は未解決である。

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
2. 完全なGo 1.27.4 toolchain、module corpusと選択されたbuild graphを認証する。sqlite 1.62.0 / libc 1.80.1 / x/sys 0.50.0のroot go.mod実bytesは後段の範囲で受入れ済みだが、完全source corpusや選択graphを検証済みとはしない。
3. 実行時の無通信と、外部から強制するwall/CPU/memory/storage/output上限を検証する。contextや事後ファイルサイズ観測だけでは強制上限にならない。build時の予算は別に決める。
4. 認証済み入力と隔離条件が揃ってからcompile-onlyとformat結果を確認する。runtime入口の有効化とprovenance/output保持はその後に別レビューし、D01–D03へ進む。
5. 制限・unknown・予想外の結果が出たら停止し、勝手に上限を上げたり再送・再実行しない。

現在は実行環境未成立。隔離準備の限定probeも権限制限で停止しており、ネットワーク共有への変更や権限昇格で迂回しない。mainのNO_GO表示だけを安全な実行許可とはしない（import初期化はmainより先に起こり得る）。

## 公開状態と境界

本資料は公開資料・ロードマップの同期と、PR #112で行った下記Intel Mac native CI対象除外を記録する。製品コード、認証・権限、DB、provider/client登録、Site本体は変更しない。公開JSONの配信確認とSite実画面の受入れは別であり、実画面は未検証のまま。各工程の過去観測時刻を保持し、全33工程を今回再検証したとは扱わない。

[current-statusの既存設計](./web-current-status-design.md)にある実装NO_GOと失効・状態・local認可の独立境界を維持する。

## Intel Mac CIの対象変更

本人の指示によりPR #112でTrialとReleaseのIntel Mac native jobを対象から外した。Apple Silicon・Windows・Linuxの既存検証、race/count、各時間上限、checksum/provenance、配布対象は維持する。Intel Mac（darwin/amd64）のcross-buildは残るが、native binary smokeとfull native race testは未検証であり、Trialのmanifestにもその範囲を記す。

[PR #112のTrial](https://github.com/g-kari/devsecops-console/actions/runs/44233264864)は旧headで初回・限定再試行ともinternal/store packageの10分上限を超過した。その失敗履歴は保持し、この対象変更を遅延原因の修復やIntelでの成功と扱わない。新しい自然CIの結果とも区別する。Release workflow自体はこの変更の検証として実行せず、tag作成・Release公開も行わない。R3合成driverや79認可negativeの未実行状態は変わらない。

## PR #112の統合後確認

PR #112を2026-11-18 05:12:18 UTCにmain 22c4008fへ通常統合。統合後Check 44242593703はattempt 1で全6 job成功（05:17:58 UTC）、Trial 44242593076はattempt 1で全9 job・6 ready成功（05:26:29 UTC）。6実配布ZIPのCRC・checksum・manifest/source・candidate内bytesを独立受入れ済み。公開JSONとmainの一致を確認したが、Site実画面の受入れではない。

Intel Mac native jobを対象外とし、Linux amd64・Windows amd64・Darwin arm64のnative検証を維持。Darwin amd64を含む6対象のcross-build配布は維持するが、Intel Mac native smoke/full raceは未検証。旧Intel package timeoutの2失敗は履歴に残り、原因修復とは扱わない。Release workflowの実行・tag作成・正式版公開はしていない。push lintの既存63 issuesはcontinue-on-errorで残る。 [Check](https://github.com/g-kari/devsecops-console/actions/runs/44242593703)と[Trial](https://github.com/g-kari/devsecops-console/actions/runs/44242593076)の成功は、R3のGo/SQLite実行を意味しない。

## 依存宣言の限定受入れ

一段目24組の依存宣言について、新たに6組のgo.mod実bytesを固定mainのgo.sum期待h1と照合し、受入れは15/24から21/24へ増えた。残るsortutil/strutil v1.2.1の2組は読取timeoutで停止、x/sys v0.49.0は期待 /go.mod hashがなく未取得。これは宣言資料であり、MVS選択graph・target import closure・完全source corpus・toolchain認証・Go/SQLite実行ではない。

3 rootはsqlite v1.62.0、libc v1.80.1、x/sys v0.50.0。一段目は重複前33宣言、異なるmodule/versionが24組。既受入れroot libcを含む21組が期待h1に一致した。宣言versionの混在だけではMVS競合と断定しない。

前工程では8組がtimeoutで15/24だった。今回はその8組だけを同じ公式proxy URLへ各1回、並列2・socket 20秒・応答64KiB・redirectなしで読み、6組を受入れ、2組は再びtimeoutとなった。初回記録は保持し、今回内の追加再試行・代替取得は行っていない。20秒はsocket上限で、全体wall上限ではない。timeoutはHTTP status/bodyなしで、拒否やupstream障害とは断定しない。

[固定mainのgo.sum](https://github.com/g-kari/devsecops-console/blob/22c4008fd7c71dcd0d3993bc6423c5fa102e9d61/go.sum)とのh1照合であり、新規sumdb照合・署名認証・全ソース検証ではない。通常appのLinux成果物から読み取った28依存のbuild infoも、R3の選択依存や全targetの不要依存を証明しない。tool/testらしい名前やindirect属性だけで除外しない。

## 隔離runnerと依存絞り込みのR2契約

隔離runnerの前提をR2で独立レビュー。metadataによるmodule選択、認証済sourceの受入れ、target package loading、closure固定、compile-only、別の入口有効化レビューを分離した。Pythonの契約モデルは2正例・114負例を実行済みで、全ての模擬receiptが揃っても実行NO_GOを維持する。実runnerの隔離・資源上限・Go/SQLite実行の検証ではない。

未成立のrunner所有・隔離、無通信と外部強制の資源上限、固定Go toolchainと入力corpusの認証を先に確認する。認証済metadataだけのmodule選択と、認証済sourceを読むtarget package loadingを分離し、不足入力を発見したら停止して別の限定取得・受入れへ戻す。closureとmissing-inputゼロを固定した後にcompile-onlyを検討し、runtime入口の有効化は別レビューとする。既存制限の緩和や無条件再試行はしない。

- 新規に所有・隔離された使い捨てrunner、既存データ/資格情報/共有cacheの非混入、unprivileged実行、process tree全体の外部監督と証拠退避先を実証する必要がある。新directoryや既存CI成功だけでは満たさない。
- Go 1.27.4と標準libraryを含む配布物、linux/amd64・CGO off・固定tags・GOWORK off・自動toolchain取得なしを固定する。metadata欠測やpackage loadingで不足が判明した場合は停止する。
- root最小宣言、24組の一段目宣言、MVS選択module graph、target import closure、app binaryの依存一覧は別の証拠である。絞り込み候補のmoduleを根拠なしに削除していない。
- runtime案の45秒wall/30秒CPU/128 MiB、1 worker・1 connection・3 cases、case当たり10秒、fixture 2 files/2 MiB、出力1 MiBは未校正の提案値。build/resolve予算は別であり、contextや事後サイズ観測は強制上限を代替しない。
- Pythonモデルの合格は契約の整合性だけ。実runnerの能力、Go挙動、安全なactivation、D01–D03成功を示さない。全実receiptは未成立で、runtime NO_GOを維持する。

初回設計ではpackage closureとsource認証の順序に循環があり、独立レビューで分離した。bool/intを同値とするモデルの比較も厳密型判定へ補正した。初回結果を破棄せず、R2の限定受入れと区別する。

公式資料: [Go Modules Reference](https://go.dev/ref/mod#require-directive)、[Lazy loading](https://go.dev/ref/mod#lazy-loading)。これらは段階分離の設計根拠であり、固定future toolchainの実挙動を未実行のまま証明するものではない。

## PR #113の統合後確認と今回の宣言入力

PR #113を2026-11-18 12:20:08 UTCにmain efcf63daへ通常統合。事後Check 44302933916はBrowser.getVersion timeoutで初回失敗し、証拠保全後の同SHA failed-job限定1回再試行（attempt 2）で12:37:43 UTCに成功。原因修復とは扱わない。Trial 44302933824はattempt 1で全9 job・6 ready成功、candidateと6実配布ZIPを独立受入れ済み。公開2ファイルのmain/raw一致は確認済みだが、Site実画面の受入れではない。

新たに受入れた6組はbigfft v0.0.0-20230129092748-24d4a6f8daec、x/mod v0.42.0、cc/v4 v4.30.6-0.20261101114202-1b9d1a076f6b、ccgo/v4 v4.38.1、gc/v3 v3.2.0、goabi0 v0.2.0。今回の期待hashは[固定mainのgo.sum](https://github.com/g-kari/devsecops-console/blob/efcf63dab7bd2df47822431ee5249855e61c7198/go.sum)で、前工程のseedと全文一致。新規sumdb・署名認証、module ZIP取得やsource実行はしていない。

残る宣言入力2組の取得失敗とx/sys v0.49.0の期待hash欠測を保持し、実runner所有・隔離・無通信・外部強制上限と固定toolchainの能力証拠を先に確立する。metadata選択、認証済sourceの受入れ、target package loading、closure固定、compile-only、別のruntime入口レビューという順序を維持する。不足や不明時は停止し、無条件再試行・制限緩和・事故環境のclean仮定はしない。

[PR #113](https://github.com/g-kari/devsecops-console/pull/113)・[事後Check](https://github.com/g-kari/devsecops-console/actions/runs/44302933916)・[事後Trial](https://github.com/g-kari/devsecops-console/actions/runs/44302933824)の成功は、隔離runner/R3 runtimeの実証ではない。Intel nativeとSite visualは未検証、lint63件は既存のcontinue-on-errorとして残る。
