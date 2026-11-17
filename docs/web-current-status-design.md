# Web current-statusの受入条件とoffline状態遷移設計

**設計資料として受入れ済み。実装・動的試験の受入れではありません。allow-producing受入ロジック、VerifiedIdentityからSessionSnapshotへの変換、実ログイン・session・runtime統合は未実装／NO-GOです。**

2026-11-15T12:54:06.713Z時点で、current-status受入条件12項目、公開provider契約の対応、7状態・18遷移・37否定シナリオのoffline設計を整理し、設計の独立レビューを終えました。37件は静的な期待結果の設計であり、実行テストの合格件数ではありません。次の実装工程は未割当です。K275全体は未完了です。

DevSecOpsの基準はmain `648c2852f30e0de8f8c3a8ceb56eb7238d6aa8d4`、providerの公開sourceは `473da3d7ab4ad5b2ba17e909d92a22c3e98b0b70` に固定します。sourceの読取は実deployment・登録client・TLS・DB・実tokenの適合検証ではありません。

以下は受入条件、provider sourceで補えた根拠、consumer側の状態遷移の順に記載します。最初の受入条件表の「未確定」は条件整理時点の区分です。次のprovider対応表でsource根拠が増えた箇所も、実deployment適合やpositive gateが解決したことを意味しません。

## current-status受入条件（12項目）

identity、current-status、local認可を分離します。署名有効・token expiry・受信時刻の更新だけで現在状態を証明しません。表の必要情報は概念上の証拠であり、新API/schemaではありません。

| ID | 境界・必要情報 | 現mainの証明範囲／不足 | 拒否条件（提案） | positive gate に最低限必要な証拠 |
| --- | --- | --- | --- | --- |
| CS01 | 署名済み identity と現在状態の分離 | **既存**: private な VerifiedIdentity、変換 API なし。**未確定**: 状態証拠の生成・受入 | 有効署名、token expiry、role claim、Revoked=false だけで状態確認済みと扱う | 検証済み identity と独立した状態証拠が必要であるという境界を保持する設計。S1/S2/S4 |
| CS02 | 状態源の権威・認証・取得対象 | **未確定**: RP 用に利用可能な状態源、認証方式、応答完全性／意味論 | 欠測、未認証、自己申告、出所不明、取得失敗、曖昧な空応答、unsupported／不明状態を active にする | 対象 provider revision の公開仕様／実装根拠で状態源・対象 token/session・応答保証・error semantics を特定。実環境適合性は後続の許可済み検証で別途確認。endpoint を創作しない。S1 |
| CS03 | exact issuer | **既存**: ID token は https://id.0g0.xyz に固定。**未確定**: 状態証拠とのissuer対応 | 別 issuer、正規化／fallbackによる同一視、状態源のissuer未確定 | 認証された状態源が同一issuerの状態を示す証拠。レスポンスへのiss文字列追加だけでは足りない。S1/S2 |
| CS04 | exact RP client / audience | **既存**: 単一string audと任意azpを設定clientに照合。**未確定**: 状態証拠のRP帰属 | 他client、client不明、IdP-origin audienceをRP clientと同一視 | RP clientに結び付いた状態問い合わせ／応答の契約。既存docsが記すintrospection JWT枝はIdP-origin audienceを検証するため、RP ID tokenをそのまま使える証拠とはしない。S1/S2 |
| CS05 | pairwise subject と状態対象の対応 | **既存**: issuer/client を照合した ID token の sub を不透明な識別子として保持し、cid/scope の存在を拒否。client固有pairwiseでの発行は既存docに記録されたprovider契約上の前提で、この工程ではprovider原典・実deploymentを再検証していない。**未確定**: 状態源のsubject namespaceと対応 | 内部user IDとpairwise subjectの文字列比較、email/GitHub名での代用、別subject／対応不明 | 正確なissuer＋client＋pairwise subjectに結び付く認証された対応証拠。access token由来の内部subjectから対応を推測しない。S1/S2/S3 |
| CS06 | provider session / local session / login世代の対応と範囲 | **既存**: identityはsession handleを提供せず、SessionSnapshotにはsession ID/client fieldなし。**未確定**: providerがどの粒度の状態を提供するか | account単位の正常を個別sessionの正常とみなす、別session／世代に流用、対応不明、過去sessionの観測で新sessionを有効化 | account・provider session・RP/local sessionの各粒度と対応手段、失効が及ぶ範囲を明示。全粒度がproviderから得られると仮定せず、不足する保証は未達のまま。現構造にfieldを足すだけでは証明にならない。S1/S2/S3 |
| CS07 | 失効・ban・logout・削除等の意味論 | **未確定**: 各signalがどの対象／世代へいつ効くか。**既存**: policyはtrusted Revoked=trueを拒否 | 適用対象の失効／ban／logoutを観測してなお許可、不明／未対応signalを非失効へ変換、関連性不明のまま許可 | 状態一覧、適用範囲、効力発生、解除／再認証条件の契約。logoutが全RPへ伝播すると仮定しない。対象local session自身のlogoutはそのsessionを再許可しない設計が必要。S1/S3 |
| CS08 | 観測の新しさ・有効範囲・clock | **未確定**: 権威ある観測時刻／version、鮮度判定、最大許容staleness、clock関係 | 古い／期限切れ、未来／解釈不能な観測、鮮度を証明できない、receipt timeだけ更新、tokenの一時間寿命をstatus TTLに代用 | source保証と製品側の許容遅延を区別したレビュー済み鮮度方針、境界値、clock異常時の拒否。秒数・TTLはこの資料で発明しない。S1/S2 |
| CS09 | 観測順・replay・失効後の再許可 | **未確定**: 単調version／epoch等の利用可否、失効後再認証の規則 | 古いactiveが新しい失効を上書き、同じ証拠の再受信で延命、順序不明の衝突、解除根拠なしの復活 | 同一対象／世代内の順序を証明する仕組み、replay時の扱い、失効ラッチと解除条件。version fieldの存在を仮定しない。証明不能時はdenyを維持し、将来の明示再認証を別に設計。S1/S3 |
| CS10 | 状態確認から利用までの競合・再確認 | **既存**: Policyは呼出時のrole snapshotで判定。**未確定**: 状態更新／logoutとの競合と確認頻度 | 古い許可結果の使い回し、レビュー済みの適用境界・順序点で失効が反映済みなのに新たな許可／副作用開始を認める、またはその境界で定めた取消・中断方針に違反して継続する、必要な実行時再確認の欠落 | session発行時・要求時・変更実行時のどこで何を再確認するか、競合時の順序／取消方針、満たせる失効反映遅延を定義。瞬時の全失効を保証したと主張しない。状態観測・ローカル反映・最終許可判定・副作用確定の順序点と取消不能範囲を区別し、未確定の間はpositive条件を成立させない。S3/S5 |
| CS11 | 証拠の完全性と安全な失敗 | **未確定**: 状態応答schema／上限／必須値。**既存**: token入力の上限と固定error | 必須情報欠落、型不正、未知schema、不整合／曖昧値、上限不明の入力を推測補完して許可 | 実契約に基づく最小schema、上限、error taxonomy、秘密を記録しない証跡方針。現token parserの合格を別形式statusの検証済みとしない。S1/S2 |
| CS12 | identityからの移行とlocal authorizationの独立 | **既存**: local role/scope、connector認証は独立。**未確定**: positiveなsession発行条件全体 | 上記未確定が残るのにsession化、status activeからrole付与／connector取得／外部操作承認へ拡張、ID token寿命をsession寿命へ無条件転記 | CS01–CS11の証拠と拒否試験設計をレビューし、assertion期限・status有効範囲・local session方針の関係を明示。それでもこの資料だけでruntime導入GOにはならない。S1/S3/S5 |

## 受入条件を満たすための追加確認

1. 上表の未確定を、**revisionを固定した公開provider契約／実装根拠**に対応付ける。現在資料のintrospection注意を解決せずRP ID token対応としない。公開資料で実deployment一致まで証明できない箇所は別欄に残す。別repo調査や実provider確認は、この受入条件整理では実施していない。
2. 情報が提供されない場合は「取得できるはず」で埋めず、その保証を必要とするsession機能をNO-GOのままにする。信頼済みboolや現在時刻だけを渡す成功fixtureは、権威・対応・鮮度・失効の証拠にはならない。
3. 状態源契約が確定した範囲に限り、失効／ban／logout・混同・欠測・古い観測・境界時刻・順序逆転・再送・競合を含むnegative matrixとpositive条件を独立レビューする。初めて**限定offline受入ロジックの実装範囲を決めるGO候補**になる。テスト実行、実login、runtime接続のGOや本番受入とは別。
4. session発行／runtimeへ進む前には別工程のnonce単回消費、PKCE/state/callback、session store/cookie、CSRF/origin、route/object scope、実IdPと設定の検証が必要。本表はそれらを代替せず、実施・完了とも主張しない。

## DevSecOps根拠 S1–S5

- S1: [web-oidc-verifier.md](https://github.com/g-kari/devsecops-console/blob/648c2852f30e0de8f8c3a8ceb56eb7238d6aa8d4/docs/web-oidc-verifier.md)、特に71–92行。provider側の記述は同docの既存レビュー記録として参照し、今回はproviderを独立検証していない。
- S2: [oidc.go](https://github.com/g-kari/devsecops-console/blob/648c2852f30e0de8f8c3a8ceb56eb7238d6aa8d4/internal/webauth/oidc.go)、40–68、99–179行。
- S3: [policy.go](https://github.com/g-kari/devsecops-console/blob/648c2852f30e0de8f8c3a8ceb56eb7238d6aa8d4/internal/webauth/policy.go)、50–62、111–145行。
- S4: [oidc_test.go](https://github.com/g-kari/devsecops-console/blob/648c2852f30e0de8f8c3a8ceb56eb7238d6aa8d4/internal/webauth/oidc_test.go)、100–139行。既存非変換テストの存在を確認。新しい動的合格ではない。
- S5: [web-auth-contract.md](https://github.com/g-kari/devsecops-console/blob/648c2852f30e0de8f8c3a8ceb56eb7238d6aa8d4/docs/web-auth-contract.md)、独立trust boundary／local policy／remaining integration。

## 公開provider sourceとの対応

以下の①は固定sourceの記述・処理、②はsourceでも不足する契約やconsumer側の設計課題、③は実環境で別途必要な検証です。HTTP説明はコード読取に基づき、実endpointの検証結果ではありません。最初に残課題を分類した表であり、続くoffline設計はその一部を具体化します。

| ID | ① 公開sourceで確認したこと | ② sourceでも不足／consumer側未設計 | ③ deployment・登録等の別検証 |
| --- | --- | --- | --- |
| CS02 | P1のintrospectionはP5のBasic service認証を要求。refresh token hashを検索し、revoked_at、service_id、expiry、user存在／banを確認。認証失敗401、入力不備400、DB例外500、対象不明はactive:false。active:true応答はiss/token_type/sub/exp/iat/scope。P7/P12のDB読取を参照。 | JSON単体に認証証拠はない。信頼された取得経路と、どの提示refresh tokenへの応答かという関連付けが必要。HTTP 200・false・500を一律成功や同じ失効理由としない。取込上限／取得失敗／応答競合を扱うconsumer契約未設計。 | TLS／正しいoriginと経路、稼働revision、認証可能な登録client、許可済みcredentialの安全な管理、DB環境と応答形式の適合。今回確認・取得なし。 |
| CS03 | P1 refresh枝のissはenv.IDP_ORIGIN、JWT枝はP3でissuerとaudienceを双方env.IDP_ORIGINに照合。P2のID tokenも同envをissuerにする。 | sourceは固定URLそのものを保証しない。DevSecOpsの固定issuerと取得経路の真正な一致が必要。文字列iss一致だけでは経路を認証しない。 | 実IDP_ORIGIN／公開origin／署名鍵が期待issuerに対応するか。secret値の閲覧を要求する設計ではなく、後続の許可済み検証で保証する。 |
| CS04 | P1 refresh枝は認証service.idとtoken.service_idを比較。JWT枝はaud=IdP-originに加えcid=service.client_idを要求。P2の通常RP access tokenはaud=clientId、resource指定時はaud=resource、BFF tokenはaud=IdP-originだがcidなし。ID tokenはaud=clientIdかつcidなし。したがって通常発行されたRP ID tokenを直接introspectionへ渡す対応経路は成立しない。通常RP access tokenのaudがIdP-originと異なる場合もJWT枝では不一致となる。resource指定を含む全access tokenの不適合を一律には主張せず、IdP-originと同じresourceを持つ特殊tokenの発行可否は未確認。 | refresh枝は候補になるが、応答にclient fieldがないことだけで不可能とはいえない。認証済み要求のclient contextと対象tokenの所有権照合を結び付けるconsumer契約が必要。IdP-origin向け特例tokenを創作してJWT枝を通さない。 | consumerが使う登録client種別／認証方式。metadataのtoken_endpoint_auth_methods_supportedにnoneがあっても、このintrospectionがpublic client無認証対応とはならない。 |
| CS05 | P2 ID発行とP1 refresh introspectionはともにP6 generatePairwiseSub(client_id,user_id,PAIRWISE_SALT)を使用。同一入力設定なら同一計算。salt有無で式が変わる。access tokenは内部user.idをsubとし、JWT introspectionはpairwiseへ変換。 | これはprovider sourceでの発行／変換関係の確認でありDevSecOps verifierがpairwise性を証明するわけではない。salt／client世代の変更や別transactionとの混同をconsumerが扱う必要がある。email／内部subの直接比較で代用しない。 | 実発行と状態問い合わせのclient・salt設定の継続性、登録clientとsubject対応。salt値を取得・記録する必要があるとはしていない。 |
| CS06 | P2/P7はrefresh tokenごとにuser_id/service_id/family_id等を保持。P1応答はその提示tokenの状態でありfamily/session IDは返さない。P9/P14のBFF sessionは別テーブル。P11はfamilyを引き継いでrefreshを回転し、ID tokenを再発行する呼出しはない。 | responseのID欠落は保証不能の証明ではない。consumerが認証されたlogin/token exchangeから保持する対象refresh tokenとlocal transaction/session/世代の結び付きを証明できれば補える候補。ただしその保管・相関・rotation時更新・旧応答破棄の契約は未設計。refresh activeはBFF sessionや全RP sessionのactiveを証明しない。 | 実clientがどのtokenを取得し、local sessionにどう束縛するか。実token取得・保存・client登録はこの工程外。 |
| CS07 | P1はrevoked token／期限切れ／user欠落／banをactive:falseとする。P10 refresh revocationはservice所有権を確認して個別tokenを失効、未知／既失効でも200。P9 logoutは提示Bearerのjti、指定BFF session、提示refresh tokenをそれぞれ処理するコードで、全RP logoutとは書かれていない。P12 banUserWithRevocationはuser ban・refresh全失効・MCP削除・BFF失効をbatch化。 | active:falseは理由を区別できず、rotation中もfalseになり得る。単一refresh無効＝全session ban／logoutと推論しない。個別token→local session停止方針、local logout、再認証・解除条件はconsumerで定義する必要。logout handler外の全middleware／全callerは今回監査しておらず、BFF限定というコメントを経路認可の実証とはしない。 | 対象logout／ban経路が実際に呼ばれる条件、実DBと反映、RP sessionが要求する失効範囲。全RPへの伝播や即時反映は未証明。 |
| CS08 | P1はtoken DB読取→user DB読取を順に行う。refresh expiry比較はexpires_at < 現在時刻で、応答exp/iatは秒にfloorしたtoken失効時刻／作成時刻。観測時刻・versionではない。P13 service lookupには5分cacheがある。 | 単一原子的な全状態snapshot／即時最新性は証明されない。認証済み要求の開始／完了区間、trusted clock、最大許容遅延、再照合点を組み合わせた保守的契約は設計可能だが未定。response.expをstatus TTLとせず、receipt time更新を再観測としない。5分はservice cache実装値でありstatus鮮度の承認値ではない。 | DB／cache／通信の観測特性と許容失効遅延の合意。期限制御をconsumerで保守的に行う境界試験、時計異常時の拒否。即時・global revocation保証は未検証。 |
| CS09 | P15は旧refreshをrotation失効させ、新token発行へ進む。同時再提示の30秒判定とreuse時family失効があり、P7にはrotation理由だけを対象にした復元処理がある。P1はrevoked理由を返さない。P8はaccess jti blocklistで、refresh familyとは独立。 | 状態応答に順序番号はないが、consumerの単一flight／request sequence／session世代・rotation世代との一致確認により古い応答破棄を設計する余地がある。要求番号はprovider側の状態versionではなく、並列要求の開始順だけからDB観測順を証明できない。30秒を状態TTLや再許可窓へ流用しない。 | 実rotationとlocal管理の相関、失効反映前後の競合試験、失効後再許可の明示条件。今回合成runtime試験も実tokenもなし。 |
| CS12 | refresh introspectionにはclient所有権＋pairwise identity＋token有効性＋user/banの限定source契約が実在する。ID token直接introspection、audience等が不適合な通常RP access tokenによる代用、または未確認の発行・対応関係を仮定した代用、signatureからのcurrent status推論は不適切。 | **NO-GO: allow-producing受入ロジック／SessionSnapshot変換／runtime。** ただし「refresh要求の由来とlocal session世代への対応を管理し、古い／失敗／不一致応答を拒否するoffline設計」は具体化できる。providerがsession ID/versionを追加することを唯一の解としない。CS06/08/09のconsumer契約・CS10の順序点・失効反映目標が確定するまではactive:trueのpositive gateを実装しない。 | 登録・稼働適合性、許可済み取得経路、session安全性・route/CSRF等の別工程。公開source照合で実loginや本番受入に進まない。 |

## 次の限定offline設計として進められること

実tokenの代わりに、意味だけを示す不透明な参照名を用いた状態遷移表を作れる。保持対象は「検証済みidentityのissuer/client/sub」「信頼されたtoken交換で得たrefresh対象へのlocal参照」「login/local session世代」「rotation世代」「要求の開始／完了区間と相関」「local失効の順序点」。これは現実の認証成功fixtureでも新schema/API実装でもない。

明示すべき遷移: 未束縛→証拠待ち、問い合わせ中のlogout／rotation、古い世代の遅延active応答、401/400/500・timeout・未知false、照合完了後から利用までの失効、許可済み再認証による別世代開始。古いactiveでlocal logoutを解除しない。単一flightでもproviderの確認後に起きた失効は見えないため、保証する最大遅延／再確認点を別に決める。期限／clock／並行性・副作用確定点の方針がない間、positive行は未確定のまま。

この設計なら架空endpoint、provider由来session ID/versionの必須化、token寿命からのTTL創作を避けて次の不足を減らせる。実装・通信・credential・client登録を伴う後続工程は、この設計資料の対象外です。

## Provider根拠 P1–P15

- P1: [workers/id/src/routes/token/introspect.ts](https://github.com/g-kari/0g0-id/blob/473da3d7ab4ad5b2ba17e909d92a22c3e98b0b70/workers/id/src/routes/token/introspect.ts)
- P2: [workers/id/src/utils/token-pair.ts](https://github.com/g-kari/0g0-id/blob/473da3d7ab4ad5b2ba17e909d92a22c3e98b0b70/workers/id/src/utils/token-pair.ts)
- P3: [packages/shared/src/lib/jwt.ts](https://github.com/g-kari/0g0-id/blob/473da3d7ab4ad5b2ba17e909d92a22c3e98b0b70/packages/shared/src/lib/jwt.ts)
- P4: [packages/shared/src/lib/oidc-metadata.ts](https://github.com/g-kari/0g0-id/blob/473da3d7ab4ad5b2ba17e909d92a22c3e98b0b70/packages/shared/src/lib/oidc-metadata.ts)
- P5: [workers/id/src/utils/service-auth.ts](https://github.com/g-kari/0g0-id/blob/473da3d7ab4ad5b2ba17e909d92a22c3e98b0b70/workers/id/src/utils/service-auth.ts)
- P6: [packages/shared/src/lib/crypto.ts](https://github.com/g-kari/0g0-id/blob/473da3d7ab4ad5b2ba17e909d92a22c3e98b0b70/packages/shared/src/lib/crypto.ts)
- P7: [packages/shared/src/db/refresh-tokens.ts](https://github.com/g-kari/0g0-id/blob/473da3d7ab4ad5b2ba17e909d92a22c3e98b0b70/packages/shared/src/db/refresh-tokens.ts)
- P8: [packages/shared/src/db/revoked-access-tokens.ts](https://github.com/g-kari/0g0-id/blob/473da3d7ab4ad5b2ba17e909d92a22c3e98b0b70/packages/shared/src/db/revoked-access-tokens.ts)
- P9: [workers/id/src/routes/auth/logout.ts](https://github.com/g-kari/0g0-id/blob/473da3d7ab4ad5b2ba17e909d92a22c3e98b0b70/workers/id/src/routes/auth/logout.ts)
- P10: [workers/id/src/routes/token/revoke.ts](https://github.com/g-kari/0g0-id/blob/473da3d7ab4ad5b2ba17e909d92a22c3e98b0b70/workers/id/src/routes/token/revoke.ts)
- P11: [workers/id/src/routes/token/refresh-token-grant.ts](https://github.com/g-kari/0g0-id/blob/473da3d7ab4ad5b2ba17e909d92a22c3e98b0b70/workers/id/src/routes/token/refresh-token-grant.ts)
- P12: [packages/shared/src/db/users.ts](https://github.com/g-kari/0g0-id/blob/473da3d7ab4ad5b2ba17e909d92a22c3e98b0b70/packages/shared/src/db/users.ts)
- P13: [packages/shared/src/db/services.ts](https://github.com/g-kari/0g0-id/blob/473da3d7ab4ad5b2ba17e909d92a22c3e98b0b70/packages/shared/src/db/services.ts)
- P14: [packages/shared/src/db/bff-sessions.ts](https://github.com/g-kari/0g0-id/blob/473da3d7ab4ad5b2ba17e909d92a22c3e98b0b70/packages/shared/src/db/bff-sessions.ts)
- P15: [workers/id/src/utils/refresh-token-rotation.ts](https://github.com/g-kari/0g0-id/blob/473da3d7ab4ad5b2ba17e909d92a22c3e98b0b70/workers/id/src/utils/refresh-token-rotation.ts)

## Offline状態遷移設計

全状態で認可出力はありません。候補証拠を認証成功fixtureや承認済みsessionとして扱いません。要求番号をproviderの観測versionへ読み替えません。

## 1. 概念上のprivate入力とtrust boundary

以下は意味上の識別子であり、新API/schema、実credential、実token、cookieの生成ではない。この設計資料は秘密値やtoken本文を含まない。

| ID | private入力・識別子 | 信頼源と必要な束縛 | 禁止する同一視・不足時 |
| --- | --- | --- | --- |
| B01 | I = exact issuer、C = exact RP client、S = pairwise subject | 検証済みidentityと信頼されたlogin/token exchangeの同一transaction。provider取得経路も同じI/Cを認証。subjectは不透明完全一致 | email/内部user ID/別client subで補完しない。単に同じ文字列を渡すだけでは由来証拠にならない |
| B02 | T = local login transaction、L = local session参照、G = login/session世代 | 完了した認証transactionから一意に束縛。再認証は新G、旧Gは終端のまま。参照再使用・ABA防止が必要 | L/Gはprovider session IDではない。同じI/C/Sでも別LやGの証拠を移さない |
| B03 | H = 個別refresh tokenへのopaque handle | 信頼されたtoken交換が得た対象を安全な保管層で参照する概念。取得経路が実際に送った対象Hと要求を結ぶ。保管方法・鍵・秘密値は未設計/未取得 | handleはcredentialの代わりとしてproviderへ送るAPIではない。利用者提供handleを信用しない。本文/hashをログに残さない |
| B04 | R = local rotation世代、X = rotation transaction参照 | 単一writerが旧H/Rから結果を相関し、新H/新Rへ一度だけ原子的更新する。成功後も新対象の状態確認は別 | local Rはprovider family/versionでない。refresh familyはprovider内部の系譜で応答にない。BFF session/access jti/local Lと同一視しない |
| B05 | Q = 問い合わせID、E = local結果受付epoch | Qは再利用せず、固定tuple(I,C,S,T,L,G,H,R,E)と開始時刻を内部で記録。応答は信頼済みtransportがQに対応させる | bodyにQやclientを足すだけでは真正性なし。Qの大小でprovider DB観測順は証明しない |
| B06 | 経路認証・要求完了情報、response、開始m0/完了m1、時計epoch | 正しいorigin/TLS、認証serviceとC、対応する要求対象を取得側で検証。m0/m1は単調local時計。bodyの型/大きさ/必須値の契約は別途必要 | JSON単体、HTTP200だけ、受信者自己申告は拒否。m1をprovider観測時刻と呼ばない |
| B07 | local終端記録、writer/fence、最終利用点 | 全writer/replicaに対する直列化と永続性、restart時の旧callback拒否、作用先の最終チェックの証明が必要 | 複数processの単なるメモリmutexでは足りない。保証なしなら不明状態・再認証待ち |
| B08 | local role/scope、利用対象、認可設定revision | current-statusとは独立した権威。将来も利用点で別途評価 | activeからrole/connector/第三者操作承認を付与しない |

信頼境界は、利用者入力→identity検証、認証transaction→token保管参照、保管参照→認証済みprovider要求、応答transport→local状態writer、状態writer→副作用開始/確定で分ける。providerは個別refreshのtoken DB読取後user DB読取を行う。両読取の単一原子的snapshotは未証明。B01–08は将来必要なprivate入力の分類であり、本工程で取得・保存・実装された入力ではない。

## 2. 状態と順序規則

| 状態 | 意味 | 許容する次の作業（設計のみ） |
| --- | --- | --- |
| U 未束縛 | identity/transaction/対象の対応証拠がない | 対応証拠の受入審査。status利用不可 |
| W 証拠待ち | tuple束縛済み、受理可能なstatus証拠なし | 新しい単一Qを開始する候補 |
| F 問い合わせ中 | 現行Qが1件、m0固定 | 応答受入審査。前候補は開始時に無効化 |
| C 候補証拠 | 現tupleのactive応答を相関できたという記録だけ | 独立gate評価用。許可・session発行不可 |
| R 回転中 | 旧対象の受付を閉じ、唯一のXが進行 | 確定した同一Xの結果待ち。status開始不可 |
| H 保留/不明 | timeout/通信/時計/相関/回転結果など不確か。原因と回復制約を保持 | 回復可能なread-only照会失敗だけ再問い合わせ。再認証必須の原因は新T/Gへ。許可不可 |
| D 終端 | local logout/適用対象失効/現対象inactive/期限終端 | 同一Gの復活不可。新transactionの再認証だけ別Gへ |

Hでは原因と回復制約を同じGに保持し、後続の通信/時計等のイベントで厳しい制約を弱めない。T12到達、未解決X、終端/fence回復未証明、その他明示再認証必須の原因が一つでもあればT08不可。T12又はR中の時計/順序喪失ではX受付を閉じ、再認証必須を記録する。この制約を解消するのはT14の新T/Gのみで、同一Gをresetしない。

各L/Gの変更は概念上の単一writerで直列化する。Fは論理的に1件だけ。追加の呼出者は新しい送信を作らず現Qの完了を待つか拒否する。待機者も同じtupleに束縛し、結果の受信時に新しい鮮度を与えない。

timeout/取消はQの結果受付を閉じEを進める。物理的に未完了の旧要求が残っていても、新Qと同時に受理可能にはしない。古いcallbackは先にtuple/Q/Eを照合して捨てる。取消API成功をprovider処理停止の証明にはしない。transportが応答を正しいQに結べなければH。稼働複製/再起動でこの順序と終端を維持できない場合もHであり、古い候補の復元は不可。

## 3. 状態・イベント・ガード・遷移・拒否表

表の「一致」はB01–B07由来が検証され、現tuple/Q/Eと完全一致し、Dでないこと。イベント処理は同一writer内で判定と更新を一体化する。表にない入力は許可せずH（既にDならD）。

| ID | 元状態・イベント | ガード | 遷移と処理 | 拒否条件/意味 |
| --- | --- | --- | --- | --- |
| T01 | U・認証transaction完了証拠 | identity、T、対象H、Cの由来対応が確定 | W、初期G/R/Eを束縛 | signatureのみ、別T、H不明はU維持 |
| T02 | W/C・状態確認開始 | 現tuple、現行要求/rotationなし、時計方針成立 | F、新Qとm0を固定、旧候補を破棄 | 旧候補を使いながら確認しない |
| T03 | F・追加確認要求 | 同じtupleの現Qのみ | F、待機/拒否。送信を重複させない | 別Qを並列に受理しない |
| T04 | F・active:true応答 | 一致、経路認証、schema、I/S/refresh種別、期限/clockの保守的検査。確定期限終端はT16を優先、不明はH | C、m1と原応答の意味を固定しQ受付を閉じる | Cは許可ではない。未確定gateは偽のまま |
| T05 | F・active:false応答 | 信頼済み経路/Qが現対象に一致、正しいfalse応答形式 | D、候補破棄、終端記録 | 理由不明の個別対象inactiveとして停止。banや全family失効と断定しない |
| T06 | 任意・旧/重複/異なるQ/G/R/H/E応答 | 受付対象でない | 現状態を変えず破棄 | activeもfalseも新世代の状態を上書きしない。適用範囲確定の独立失効通知はT09で別処理 |
| T07 | F・401/400/500、timeout、通信断、型/上限/経路/対応不明 | 現Qの失敗 | H、Q受付を閉じE更新、候補無効 | 401=ban、500=inactive等と分類しない。未知をfalse/trueに補完しない |
| T08 | H・再問い合わせ | 回復可能なread-only照会失敗の原因解消、同一H/G/Rが確実、経路/clock回復。T12到達/未解決X/終端又はfence回復未証明/再認証必須制約が一つもない | W経由で新Qを開始可 | introspection再試行は新観測候補。旧応答再配達を新規にしない。回数/間隔/資源上限未確定 |
| T09 | U/W/F/C/R/H・local logout又は適用範囲が確かな失効 | そのL/Gへの真正な指示/証拠 | D、受付閉鎖、E/fence更新、全候補/待機者無効化 | 遠隔logout成功を待たずlocalは終端。全RPへの伝播は主張しない |
| T10 | W/F/C・rotation開始 | B04、唯一X、正確な旧H/R、所有writer | R、先にE/fence更新し候補と旧Q受付を破棄、その後送信予定 | 同時rotationや別writerは開始拒否。sourceにある30秒を再試行許容に使わない |
| T11 | R・rotation成功結果 | 現X/旧H/旧R/Gに一致、logout/確定期限終端/再認証必須制約無し、結果と新対象の由来が確定。T16の期限判定を同一writerで先に行う | 原子的に新H/新R、Wへ。新Qで別途確認 | 古いstatusは流用不可。refresh成功自体を新ID検証/現状態保証にしない |
| T12 | R・明確な失敗またはtimeout/結果不明 | 現X | H、X受付閉鎖、全候補無効、原因と同一Gの再認証必須制約を記録 | 自動rotation再送/旧H復活をしない。provider側復元処理の存在はconsumerの成功証明でない |
| T13 | R/H/D・遅いrotation結果/二重結果 | Xが閉じた/終端/新世代 | 現状態維持、結果を許可や対象更新に使わない | provider側で発行済みの可能性は残る。cleanup/revokeは別途許可/設計が必要 |
| T14 | D/H・明示的な再認証完了 | 新Tと完全なidentity/対象由来、旧Gと非同一、既知の適用失効制約に反しない | 旧GをDのまま保存し、新GをU→Wとして別開始 | 遅いactive、時刻経過、ban解除の推測、同一Gのresetは禁止 |
| T15 | W/F/C/R/H・時計epoch喪失/後退、再起動で順序不明 | local信頼状態喪失 | H、受付閉鎖、候補破棄、既存の回復制約を保持。R由来なら未解決Xを保持しX受付閉鎖・再認証必須。その他も復旧できなければ新G再認証 | wall clockだけを直して再利用しない |
| T16 | C・候補だけの鮮度不足、又はU/W/F/C/R/H・確定期限終端/期限不明 | 鮮度不足は現候補のみ。終端は束縛が確かな現Gのlocal session期限又は現H/R/Gの対象期限。旧対象の期限eventは適用しない | 候補だけの鮮度不足はC→W。確定終端は該当非終端状態→D、Q/X受付閉鎖・候補破棄・終端/fence記録。不明はHで既存回復制約を保持し、R由来ならX受付閉鎖・再認証必須 | 未束縛の期限を推定しない。Dは維持。token expをstatus TTLとして延長しない |
| T17 | C・利用/変更要求 | 将来の全positive gateとlocal認可を満たす必要 | 今回は必ず拒否。設計審査対象としてのみ記録 | C→allow/SessionSnapshotの遷移は定義しない |
| T18 | 任意・local永続化/直列化/競合解決失敗 | 終端/fenceの確実性を失う | Dなら維持、それ以外H、受付と利用を停止 | 最後のactiveへfallbackしない |

期限eventは対象種別（local session又は個別refresh対象）とG、対象期限ならH/Rを固定し、処理時に現束縛へ照合する。R中はT11の原子的更新まで旧H/Rが現対象。確定期限終端が先ならDとなり遅いrotation成功をT13で拒否する。T11処理時にも現G/sessionと現H/Rの確定期限を先に検査し、既に終端ならT16でDとする。期限前にT11が先に成立して新H/Rへ更新した後の旧H/R期限eventは破棄し、新対象に移さない。一方local session期限はGに束縛されるのでrotation成功後も適用する。時計/期限が不明ならHであり、未知を期限前へ補完しない。

T05は保守的consumer停止方針でありproviderがlocal sessionを失効した事実ではない。rotation開始が先に直列化されたなら旧QのfalseはT06、falseの受理が先ならDとなりrotation開始を拒否する。安全側の再認証増加を許容する提案でありavailability評価は未確定。

## 4. 鮮度・clockの未確定パラメータ

m0は実送信前に固定、m1は受信完了時に固定、uは最終利用点の同じ単調時計値。内部queueもm0以降に含める。区間[m0,m1]はcallerの要求期間であってprovider観測timestampではない。providerのtoken読取/user読取は別時点であり、区間内の一瞬に全条件が同時成立したとは主張しない。

| パラメータ | 決めるべき意味 | 今の状態 |
| --- | --- | --- |
| Delta_source | DB/cacheが要求時点より過去を返し得る上限、各読取の一貫性 | 未確定。有限と仮定しない |
| Delta_allowed | 製品が許容する失効観測の古さ | 未確定。source値から勝手に決めない |
| Delta_flight | 許容する要求所要時間と取消/timeoutの扱い | 未確定。m1−m0の比較基準 |
| Delta_apply | local反映から作用点までの上限/直列化保証 | 未確定。分散writerと作用先を含む |
| Clock_policy | 単調時計epoch/中断/復旧、wall clockとprovider時計の誤差上限、expiry秒丸め境界 | 未確定。token exp/iatは観測versionではない |
| Expiry_policy | token期限、identity/assertion有効期間、local session寿命の別制約と最も厳しい境界 | 未確定。無条件転記なし |
| Retry_policy | read-only問い合わせ再試行の間隔/上限/負荷制御 | 未確定。rotation再送の許可ではない |

将来の保守的な必要条件候補は「同一時計epoch、0 ≤ m1−m0 ≤ Delta_flight、u ≥ m1、(u−m0)+Delta_source ≤ Delta_allowed」であり、値とsource前提が確定して初めて評価可能。これは十分条件でも実装でもない。providerの非原子的二段読取が必要な保証と整合することを別途示す必要がある。source lagが不明ならこの条件は未成立。受信時m1からだけTTLを数えず、同じQの再配達ではm0/m1を更新しない。

expiryは観測鮮度と別に、信頼済み時計差/秒丸めを織り込んだ保守的な期限前条件を要する。providerのexpires_at < now実装をconsumerの境界許可へ直結しない。iatを未来/古い観測判定の代用品にしない。service cacheの5分、rotation判定30秒、token寿命はDelta_allowedではない。

## 5. 利用・失効競合と取消不能点

概念上の順序点: O=provider複数読取、A=local応答候補反映、V=local失効終端反映、J=最終認可評価、B=副作用開始、K=取消不能な確定点。Q番号はOの順序ではなく、local writerはA/V/Jの競合だけを直列化できる。

- VがJ/Bより先なら、そのL/Gを使った新規認可/開始を拒否する。Jの結果を無期限の許可券にしない。JとBの間を同一fenceで保護する具体的な作用先契約は未確定。
- Jの後Bの前にVが来た場合、Bでfenceを再確認できる設計が必要。それができなければこの保証を提供する操作はNO-GO。
- Bの後Kの前にVが来た場合、操作ごとの安全な中断点でのみ中止できる。transport取消やprocess停止で安全にrollbackできると仮定しない。
- Kの後にVが来た場合、確定済み効果は遡及取消できない。後続操作を止め、必要なら別途承認された補償手順へ。自動補償の承認は本設計に含まない。
- Oの後providerで失効しても通知/新観測までlocalは知らない。上記はlocal反映後の順序保証候補であり、providerでの瞬時失効、全RP伝播、進行中操作の強制取消を保証しない。

## 6. 不変条件

I01: identity検証とcurrent-statusとlocal認可を分離し、どの状態もallowを出さない。
I02: 相関tupleは要求開始後不変。現世代以外の結果は現在世代を更新しない。
I03: Dは同一G内で吸収状態。再認証は新T/Gでのみ開始する。
I04: 受理可能Qは各L/Gで高々1。Q/E再使用なし。複数物理flightの開始順をprovider観測順としない。
I05: rotation開始で旧候補/要求受付を無効化し、結果不明から旧Hへ戻さない。
I06: 同じ証拠の再配達・待機者配布・receipt更新で鮮度を延長しない。
I07: active:falseは対象inactiveの根拠に限定し、ban/family/global失効理由を発明しない。
I08: refresh family、individual token、BFF/provider session、local session、R、I/C/Sを区別する。
I09: 時計・期限・由来・順序・状態不明は候補無効。ネットワーク成功を観測最新性としない。
I10: local終端/fenceの永続性と作用点の直列化がなければpositive gateは閉じたまま。
I11: token本文・credential・provider salt・個人識別値を成果物/ログへ保存しない。追跡は概念ID/理由分類だけ。
I12: 認証再開やrotation成功はlocal role/connector/外部操作の承認を増やさない。

## 7. 未確定positive gateとGO条件

| Gate | 必要な追加根拠 | 現判定 |
| --- | --- | --- |
| G01 | B01–B06の認証transactionとrefresh対象由来、実登録client/issuer/TLS/稼働revisionの適合 | 未確認、NO-GO |
| G02 | token保管参照の安全性とlogin/session/G/R/Xの原子的束縛、crash/複製/fenceの永続性 | 未設計/未検証、NO-GO |
| G03 | Delta_source/allowed/flight/apply、Clock/Expiry/Retry方針と境界、非原子的読取の受容可能性 | 未合意、NO-GO |
| G04 | schema/型/上限/失敗分類、主体設定変更と再認証の整合、対象失効範囲 | 未確定、NO-GO |
| G05 | J/B/Kと作用先fence・安全中断/取消不能点、許容失効反映遅延 | 未確定、NO-GO |
| G06 | negative matrix独立レビュー、将来の限定offline実装範囲と検証計画の別途承認 | 否定シナリオの設計レビュー済み。実装範囲・動的検証は別途未確定、NO-GO |
| G07 | nonce単回消費/PKCE/state/callback/store/cookie/CSRF/origin/route/object scope等の別工程 | 未完、runtime NO-GO |

受入れた範囲は、固定sourceに基づくlocal側の相関・終端・遅延応答拒否の設計資料まで。独立レビューを終えてもG01–07は自動で解消せず、allow-producing受入ロジック/SessionSnapshot変換/runtimeへ進まない。

## 否定シナリオ37件（設計上の期待結果）

**未実行。fixtureやruntime試験のpassではない。** 各結果は設計レビュー/将来の試験仕様の候補。Txx/CSxxは本資料の状態遷移と受入条件に対応する。

| ID | 入力・順序 | 必須の拒否/状態結果 | 遷移 | 受入条件 |
| --- | --- | --- | --- | --- |
| N01 | 署名validだけでU→許可を要求 | U維持、拒否 | T01/T17 | CS01/12 |
| N02 | 別issuer/client又は内部user IDをpairwise subに流用 | 束縛/応答受入拒否。由来不明はH | T01/T04/T07 | CS03/04/05 |
| N03 | 同I/C/Sだが別T/L/Gのactive応答 | 現在世代を変えず破棄 | T06 | CS06/09 |
| N04 | 同Rと称する別Hへの応答 | Qに固定したHと不一致で破棄 | T06 | CS02/06 |
| N05 | Fでlocal logout、その後active受信 | D維持。古いactiveで復活しない | T09/T06 | CS07/09 |
| N06 | 現Qのfalse受入後、前Qのactive受信 | D維持、falseをbanとは断定しない | T05/T06 | CS07/09 |
| N07 | Fの間rotation開始、旧Qのactive/falseが遅着 | R又は新RのWを維持、旧結果を破棄 | T10/T06 | CS06/09 |
| N08 | false受入がrotation開始より先に直列化 | D、rotation開始拒否。安全側の再認証 | T05/T10 | CS07/09 |
| N09 | 受理済みX1成功の重複が後続X2成功より後に到着（X1未確定のままX2は開始しない） | X1でH/Rを戻さない。未受付結果は破棄 | T11/T13 | CS06/09 |
| N10 | rotationの明確な失敗又は送信後timeout、provider結果不明 | H再認証必須を保持。T08再問い合わせ/旧H復活/自動再送なし | T12 | CS07/09 |
| N11 | logout後にrotation成功が届く | D維持、新対象をlocalへ採用しない。遠隔cleanup未完の可能性を分離 | T09/T13 | CS07/10 |
| N12 | introspection timeout後新Q開始、旧Qが後からactive | 旧Qの受付epoch不一致で破棄。新Qだけ審査 | T07/T08/T06 | CS08/09 |
| N13 | 同Qのactiveを繰り返し受信/複数待機者へ配布 | m0/m1不変、候補の鮮度を延長しない | T06 | CS08/09 |
| N14 | Fで別Qを並列送信しようとする | 待機/拒否。既に旧物理flightがあっても現受付は1件 | T03/T06 | CS09 |
| N15 | 大きいQ番号だから新しいprovider状態と判断 | その推論拒否。番号はlocal相関のみ | T04/T06 | CS08/09 |
| N16 | 401/400/500/空body/不明型/巨大bodyをactiveへ補完 | H、候補無効。理由をbanに補完しない | T07 | CS02/11 |
| N17 | active:falseをfamily全失効/ban/全RP logoutと通知 | その意味拡張を拒否。現local Gの保守停止に限定 | T05 | CS06/07 |
| N18 | iat/exp、service cache5分、rotation30秒からstatus TTL作成 | G03不成立、利用拒否 | T16/T17 | CS08 |
| N19 | 要求長期滞留を無視し受信m1からだけ鮮度計算 | m0からの期間/Delta_sourceが不明又は超過なら拒否 | T04/T07/T16 | CS08 |
| N20 | wall clock後退/時計epoch喪失/restart時に保存active再利用 | H、受付閉鎖、候補破棄。復旧不可なら新G | T15 | CS08/09 |
| N21 | Fでactive受入時に現対象の確定期限超過、又は時計差上限不明 | 候補受入拒否。確定終端はT16でD、不明はH。C限定ではない | T04/T15/T16 | CS08 |
| N22 | A後V、又はJ後B前Vで古い認可を利用 | J/Bで拒否するfence必須。未実証の間はNO-GO | T09/T17 | CS10 |
| N23 | B後K前のVで任意process停止を安全rollbackと扱う | 操作固有中断契約なしでは保証拒否 | T17 | CS10 |
| N24 | K後Vで確定済み副作用が取り消せると主張 | 遡及取消保証を拒否、後続を停止。補償は別許可 | T17 | CS10 |
| N25 | O後provider失効、次観測前にlocalが知らない | 瞬時失効保証を拒否。許容遅延/source保証未確定でgate閉鎖 | T17 | CS08/10 |
| N26 | 二段DB読取の間に状態変更、atomic snapshotと称する | 原子的観測の主張拒否。G03未確定のまま | T04/T17 | CS08 |
| N27 | 二writer/split-brainで同じG/Rへ異なる更新 | H/停止。writer/fenceの実証なしではpositive不可 | T18 | CS06/09/10 |
| N28 | 明示再認証なし、時間経過/遅いactiveでD解除 | D維持。新T/Gの再認証だけを候補にする | T14 | CS07/09 |
| N29 | salt/client設定変更でsubが一致しない | 自動移行しない。束縛再審査/再認証、現応答拒否 | T01/T04/T07 | CS05 |
| N30 | RP ID token直接又はaud不適合RP access tokenで代用 | 候補経路として拒否。特殊token発行の創作なし | T01/T04 | CS04 |
| N31 | read-only introspection再試行方針をrotation POST再送へ適用 | 結果不明rotationはH再認証待ち、自動再送しない | T08/T12 | CS09 |
| N32 | activeからrole/connector権限/外部操作承認を導出 | 独立認可欠落で拒否 | T17 | CS12 |
| N33 | T12の明確失敗H後、通信/時計回復を理由にT08開始 | 原因と再認証必須制約を維持、同一Gの再問い合わせ拒否 | T08/T12/T15 | CS07/09 |
| N34 | R中の時計喪失でH、その後遅いrotation成功 | 未解決Xを保持、受付閉鎖と再認証必須を維持。遅い成功で回復しない | T15/T13 | CS08/09 |
| N35 | W/F/R/Hで現Gのlocal session期限終端が確定 | T16でD、Q/X受付閉鎖・候補破棄・終端記録。Hへの緩和不可 | T16 | CS07/08/09 |
| N36 | R中、現旧H/R期限終端が先、rotation成功が後 | Dを維持、遅い成功拒否。T11時の期限検査でも終端ならD | T16/T11/T13 | CS08/09 |
| N37 | 期限前のrotation成功が先、その後旧H/R期限event | 旧対象eventは破棄し新H/Rへ失効を移さない。現Gのsession期限ならD | T11/T16 | CS06/08/09 |

成功例fixtureは作成していない。全gate確定後にも、boundary直前/一致/直後、各競合の両順序、restart/複製、遅延・二重応答を別途検証する必要がある。

## 実装へ進む前の境界

本資料は設計済みの範囲を公開するものです。実装、動的試験、実provider・client登録・稼働deploymentの適合、実ログイン・session・runtimeは未検証です。TTL、clock、sourceの観測保証、永続fence、作用先の契約が未確定な間、allow-producing受入ロジックとSessionSnapshot変換はNO-GOです。設計受入れを実装・運用完了と扱いません。


## local-session ledger契約（文書設計のみ受入れ）

2026-11-15T15:07:27.472Zに、local-session ledgerの6処理順序点と42追加negative/crash行を文書設計として受け入れました。旧12条件・7状態・18遷移・37negativeを保持します。42追加行と37旧行は全て未実行の期待結果で、79テスト合格や網羅性証明ではありません。LG01–LG09は全て未解消で、LG09の独立レビュー部分だけが完了しました。実装/API/schema/SQL migration/allow/SessionSnapshot/runtime/実provider接続はNO-GOです。K275は部分完了、次の実装工程は未割当です。

以下のLS1–LS6は処理順序点です。既存の7状態や前節の根拠source記号S1–S5とは別で、状態数やsource参照を変更しません。節番号§0–§9はこのledger契約内だけを指します。比較更新revision・fence・readiness・readback観測もsession状態ではありません。

本追記の固定基準はmain `7b4a675b510800756fe017230a9768719820057a`。上記の既存設計と公開provider sourceの固定参照はそのまま保持します。受入時刻は文書設計の成果時刻であり、配信commitや実装コード統合時刻ではありません。SQLite・enrichmentのtransaction/CAS/readbackは比較設計の参考であり、auth ledger実装や現HTTP保護の証明ではありません。

### 0. 判定と適用範囲

**2026-11-15T15:07:27.472Zに文書設計として受入れ。独立レビュー済み、未実装・未実行。** 既存12受入条件、7状態(U/W/F/C/R/H/D)、18遷移(T01–T18)、37negative(N01–N37)をそのまま継承する。以下LS1–LS6は処理順序点であって新しいsession状態ではない。保存結果・送信履歴・owner readinessも別の観測分類であり、7状態への追加ではない。T17は常に拒否し、本契約のどの結果もallow/session/Grantを生成しない。

目的はlocal側の相関・終端・不確定結果の保持要件を明確にすること。実API、schema、SQL migration、token保管仕様、credential、login、provider呼出、成功fixtureを作らない。実装scopeの承認にもならない。

前提候補は「単一owner、同一権威DB」。これは運用事実ではない。全writer・全利用入口・dispatch・作用先が同一の排他/順序契約に従う証拠が必要。既存Storeのmutex/1 connection、file SQLiteの存在だけでは成立しない。ledgerを追加しただけで現HTTPが保護されるわけではない。

### 1. 分離する概念

- **束縛tuple B**: (I,C,S,T,L,G,H,R)。I/C/Sはexact issuer/RP client/pairwise subject、Tは完了認証transaction、L/Gはlocal sessionとその世代、Hは信頼済み交換で得た個別refresh対象へのopaque参照、Rはlocal rotation世代。意味と由来を固定するだけで、識別子の実値/保存形式/秘密の置き場は定めない。VerifiedIdentityだけでT/Hを証明しない。
- **Q,E**: 問い合わせ相関と受付epoch。現Bに結び、現受付Qは高々1。開始後のBを変更しない。閉鎖済みQを再利用しない。Qの大小はprovider読取順ではない。
- **X**: 唯一のrotation transaction相関。G/旧H/Rへの束縛。X未解決の間に次Xを始めず、後着結果で別Xを完了させない。
- **v**: local ledger比較更新revision。判定した状態を別writer更新後に上書きしないための値。全関連状態変更を比較対象に含める。vはprovider versionでもstatus鮮度でもない。
- **f**: 作用・受付の無効化を表す永続fence。Gとowner系譜に束縛し、終端・rotation開始・受付破棄などのイベントで旧証拠を使えなくする。具体的増分形式は未定。単なるvの大小を外部受信側が信用する契約はない。v/f/G/Eを同一視しない。
- **owner epoch と clock epoch**: 前者は排他的ownerの系譜、後者は単調時間の比較可能範囲。再起動で同じと仮定しない。永続化した数値を読むだけでowner取得又はclock連続性の証明にはならない。
- **terminal と recovery constraints**: Dの同G吸収性、Hの原因と再認証必須/未解決X等の制約。候補・待機者・受付Q/Xの閉鎖と同一の原子的変更に含める。再認証必須は後続の通信/時計回復で弱めない。
- **candidate**: 相関済み応答の意味と元のm0/m1/clock epoch等。許可ではない。同Q再配達/readback/待機者配布で時刻を作り直さない。実応答/secretの保存形式はここで決めない。

ID/revision/fenceの非再使用、overflow時停止、履歴保持上限、GC条件は未確定。既存enrichmentの4世代/5checkpointは流用しない。D記録又はそれと同等の非復活証明を失うGCは許容しない。有限保持を正当化する遅延上限がなければ安全な削除時点を創作しない。

### 2. 共通commitと運用停止の契約

**C1 比較と更新**: B、v、owner系譜、現state、Q/E/X、terminal、回復制約、関連期限の判定と更新は同じ権威DB transactionの一体的操作でなければならない。外部問い合わせをDB transaction内に入れて原子化したとは扱わない。競合は一方だけ成立し、敗者は現状態を再評価する。再評価は送信の自動再試行を許可しない。

**C2 線形化**: 成功を確認したcommitがlocal状態変更の順序点。確定していないcommitを成功/失敗どちらにも補完しない。Commit errorや応答喪失は保存済みの可能性がある。readbackは同一の保持済み要求・期待結果に対してmatched/missing/conflict/unknownを分ける設計候補。matchedは保存内容の証明に限定し、送信、provider未処理、所有権、現行fence、鮮度、認証成功の証明ではない。missingもprovider未処理や自動再送許可ではない。

**C3 fail-stop**: local保存失敗/不明では、D既知ならDを緩めず、他はH相当の利用禁止として扱う。ただし書込不能時に「Hが永続化済み」とは主張しない。owner readinessを閉じて新規状態受理・dispatch・作用開始を停止する必要がある。readinessはsessionの8番目の状態ではなく運用上の入口制約。

全owner停止が成立する条件は、(a)唯一ownerが実際に排他的である、(b)全入口がready判定だけでなく同一の競合制御下で開始/停止を順序付ける、(c)ready喪失時に未開始処理を失効できる、(d)旧ownerが入口を迂回して動けない、(e)再起動ownerは初期値closedで復旧審査を終えるまで入口を開けない、の全て。保存するstop flagだけでは(a–e)を証明しない。process-local bool/mutexだけで複数ownerを止められるとはしない。全ownerへの停止伝達・隔離が証明できなければ配置全体NO-GO。単なる「検知したら停止」は検知できないDB rollbackを解決しない。

既に送信/Bを越えた処理はC3で巻き戻らない。受付拒否と新規開始禁止を行い、B/K契約に従う。read-only照会の物理flightが残ることを許す場合も、受理可能Qは1件のみ。rotation不明は再認証必須を保持する。利用入口が安全に閉じた証明なしに、失敗をDBへ記録できなかった状態からサービスを続けない。

**C4 durability**: transaction rollbackは未commit local SQLの範囲だけ。電源断、fsync、storage corruption、backup、DBコピー/復元、writer交代への保証は別。DBが過去へ戻ればv/f/tombstoneも戻り得る。外部の非巻戻し根拠や旧owner隔離などの方法と実証は未定で、検知不能な復元を安全に処理できるとは主張しない。この不確実性がある環境は起動を閉じたまま。信頼境界を回復して旧writer/コピーを排除した後に新T/Gで再認証する必要があり、新認証だけでインフラ問題は解決しない。

### 3. LS1 開始commit→送信（T02/T03/T08）

W/C又はT08を満たしてWへ戻れるHについて、現B/owner/v、非terminal、現Q/Xなし、clock条件を確認する。HにT12、未解決X、fence復旧未証明、再認証必須が残れば開始不可。新QとE・開始m0/clock epochを固定し、旧候補を無効化してFを原子的にcommitする。m0は実送信前、以後のqueue時間を含める。並行呼出者は現Qを待つか拒否し、別Qを作らない。

送信対象になれるのは確認済み開始commitの現Qだけ。ただしcommit後dispatch前の確認と実transport送信の間にはraceがある。開始commit自体もdispatch前checkも「V後にpacketは絶対送られない」を保証しない。送信境界をlogoutと共通に順序付ける別契約がない場合、その強い保証はNO-GO。V後遅れて送信された旧Qの結果はLS2で拒否し、provider未処理と主張しない。今回送信そのものを実装しない。

開始commit前に停止したと確証があればこのQの開始は不成立。commit成功不明ならC3/LS6へ。commit後送信前crashでは保存Qがあっても自動送信しない。送信済み不明を含むため旧受付を復旧利用せず、LS6で候補破棄/受付閉鎖の条件を確認する。新QはT08の全条件を満たす回復可能なread-only照会だけで、旧Q再送ではない。

### 4. LS2 応答commit（T04–T07/T16）

信頼済みtransportによるQ↔実対象Hの相関証拠が前提。body自己申告は不可。現在のB/Q/E、owner/clock epoch、v/f、F、非terminalを同transactionで比較する。旧/重複/不一致応答は現状態を変えず破棄。現在対象の確定期限が成立していればactive:trueよりT16を優先してD。期限/clock不明ならHで制約を保持する。

現Qの真正なfalseはT05としてD、候補破棄/受付閉鎖/terminal/fenceを原子的に反映。現Qの真正なactive候補はschema/経路/identity/時間条件が未成立なら採用せずH。必要条件が将来確定してもC候補まででallow不可。T07失敗はH、Q受付閉鎖/E更新、候補無効化。応答候補・失敗・終端いずれも保存結果不明ならC3/LS6。重複readbackでm0/m1を更新しない。

### 5. LS3 終端commit（T05/T09/T16）

真正な適用範囲が分かるlogout/失効、現対象false、現G/session又は現H/R/Gの確定期限を受理する。現状態と対象範囲を比較しD＋terminal＋旧fence失効＋Q/X受付閉鎖＋候補/待機者無効を同transactionで保存する。遠隔logout完了は待たない。未束縛/旧対象期限を現Gへ推測適用しない。

Vはこの確定commit。Vが先なら旧結果・旧作用要求は拒否する。V保存不明ならC3で入口停止し、旧Cへfallbackしない。LS2 falseが先ならrotation開始不可、LS4開始が先なら旧Qのfalseは破棄。Dは同Gで吸収、新T/G以外で復活しない。新T/Gも既知の適用失効制約、owner/DB信頼回復、完全な由来の条件を満たす必要がある。

### 6. LS4 rotation intent→送信→結果（T10–T13/T15/T16）

唯一ownerが現G/旧H/R・非terminal・唯一X・回復制約なしを比較し、R/Xを束縛、旧Q/候補閉鎖、E/fence更新を送信前にcommitする。実rotationを未実装のまま、この順序だけを契約化する。commitとprovider送信は一つのtransactionでない。dispatch check後のVと実送信のraceを消したとはしない。送信済みが不明でも自動再送/旧H復元は不可。

成功結果の取込は現X/G/旧H/R、非terminal、再認証必須なしを再比較し、同writerで現G/sessionと現旧H/Rの期限を先に判定する。確定終端ならD、未知ならH＋X受付閉鎖＋再認証必須。期限前が確かで結果/新対象の由来も確かなら新H/新Rを原子的に保存してWへ。新status確認は別Q。成功自体は認証/現状態保証でも権限増加でもない。

明確失敗又はtimeout/不明(T12)、R中clock喪失(T15)、R中期限不明は、H・未解決X/原因・X受付閉鎖・同G再認証必須を保持する。後着成功/重複で解除しない。送信前crashで未送信を確実に示せない場合も同じ保守制約。実装時に「確実に未送信ならRを戻す」という新遷移を追加することは本契約では認めない。

期限競合: 旧H/Rの確定期限が先ならDで遅い成功拒否。期限前の成功取込commitが先なら旧H/R期限eventは捨てる。一方現G/session期限はrotation後もDを生む。結果commitが曖昧なら新Hを採用済みとも旧Hが有効とも補完しない。providerで新対象が発行済みの可能性と、local不採用を分ける。cleanup/revokeは本契約の自動操作ではない。

### 7. LS5 最終利用と作用（T17、J/B/K）

**本工程は常に拒否。** 将来の検討条件だけを記す。Jはidentity/status/local認可/CSRF/object scope/command/別承認の最終審査、Bは作用開始、Kは取消不能確定。Policy.AllowsのboolはBへの永続許可券ではない。

同一権威DB内だけの作用なら、現Btuple/v/f/terminal/期限/現在policy revision等の評価と対象writeを同じtransactionで行う案が考えられる。Vが先にcommitすれば旧作用を拒否、作用commitが先なら後続Vが既存効果を取消したとは言わない。DB transaction内で途中の外部I/Oを呼ぶ設計は同一DB作用の範囲外。

外部作用は受信側fence検査・idempotency・VとB/Kを含む共通順序保証が必要。fence文字列を送るだけ、重複抑止だけ、outboxに記録するだけ、dispatch直前checkだけでは不足。VがJ後B前ならBで拒否できる契約、B後K前なら操作固有の安全中断点、K後なら後続停止だけを区別する。必要な受信側契約がない操作はNO-GO。送信済み外部作用をlocal transaction rollback/process killで取消せるとはしない。

### 8. LS6 restart/readback（T06/T13–T16/T18）

起動時のowner readinessはclosed。唯一owner性、権威DBの非巻戻し/履歴完全性、旧owner隔離、terminal/制約、現在epochの保証を検証できるまで受付/dispatch/利用を開けない。readback matchedだけではこれらを復旧できない。DB復元/複製/ABAを検知不能なら安全復旧手順未成立のため停止、信頼を再構築するまでは新認証も運用再開の根拠にしない。

Dを保持し、他状態の保存candidate/古いQはclock連続性や順序保証を推測して復活させない。新clock epochへのm0/m1移植は禁止。R又は未解決Xがあれば受付閉鎖、H/再認証必須。その他もT15で候補破棄/受付閉鎖、既存回復制約を保持。回復可能なread-only失敗だけT08全条件が再成立すれば新Qへ進む候補を検討できる。fence/終端/clockの確実性が戻らなければ同G再開不可。

readback観測のmatched/missing/conflict/unknownはsession stateの追加ではない。matchedはhistorical storage proofであり、現owner/fenceの証明と別。conflict/unknownは停止を維持。missingも安全な再送やID再使用を許さない。commit後ack喪失とcommit前失敗を区別できない場合、重複送信で解決しない。D/H制約と未解決Xの保持を証明できない復旧はNO-GO。

### 9. clockと未確定事項

provider sourceの観測・lagとlocal単調clockを分離する。m0/m1/uは同じclock epoch内でのみ期間比較可能。wall clock/provider expとの対応、秒丸め、誤差上限、suspend/restart時の扱いは未確定。provider二段読取を一瞬のsnapshotとしない。Q順序、receipt時刻、iat、exp、enrichment世代をprovider観測versionへ変換しない。

Delta_source/allowed/flight/apply、Clock/Expiry/Retry方針、schema上限、tombstone GC、durability/配置/owner取得/復元、送信境界、作用先の契約は未確定。元設計の必要条件候補は十分条件ではなく、値を埋めない。本文はG02/G05の設計を細分しただけでG01–G07の解消を認定しない。下表のLG01–LG09が閉じるまでcandidateも実運用allowに変換しない。


### 既存条件・遷移との対応

| 元遷移 | 契約位置 | 維持する制約 |
| --- | --- | --- |
| T01 | §1/§3 | identityだけで対象由来を作らない、U→Wの前提 |
| T02/T03 | §3 LS1 | 候補無効化、単一受付Q、待機/拒否 |
| T04 | §4 LS2 | 相関・期限判定後でもC候補のみ |
| T05 | §4/§5 | 現Q false→D、意味拡張なし |
| T06 | §3/§4/§8 | 旧tuple/Q/E応答破棄、現状態不変 |
| T07/T08 | §3/§4/§8 | H原因保持、回復可能なread-only照会だけ新Q候補 |
| T09 | §5 LS3 | D、Q/X閉鎖、fence/候補無効化 |
| T10/T11 | §6 LS4 | intent先行、唯一X、期限先検査、新対象はW |
| T12/T13 | §6/§8 | H再認証必須・未解決X保持、遅い結果不採用 |
| T14 | §5/§8 | 新T/Gのみ、既知失効制約とインフラ復旧は別条件 |
| T15 | §6/§8/§9 | clock epoch喪失で候補破棄、R由来制約を保持 |
| T16 | §4/§5/§6 | 確定期限D、未知H、旧H/Rと現G期限を区別 |
| T17 | §0/§7 | 必ず拒否、J/B/Kは将来要件のみ |
| T18 | §2/§8 | 保存不明はfallback不可、全入口停止の成立条件 |

| 元条件 | 契約対応 | 未解消 |
| --- | --- | --- |
| CS01 | §0/§1/§4/§7 | identityと現在状態の独立証拠 |
| CS02 | §1/§3/§4 | 認証transport・取得対象・実稼働適合性 |
| CS03 | §1/§4 | exact issuerの由来対応 |
| CS04 | §1/§4 | exact RP client帰属 |
| CS05 | §1/§4 | pairwise subjectと対象の真正な対応 |
| CS06 | §1/§3/§5/§6 | local世代/個別refresh/provider粒度の由来 |
| CS07 | §2/§5/§6/§8 | 適用失効範囲、永続terminalと再認証 |
| CS08 | §4/§6/§8/§9 | source lag、clock/expiry/TTL全方針 |
| CS09 | §1–§6/§8 | 全owner順序、replay/ABA/復元の証明 |
| CS10 | §2/§3/§6/§7 | 送信race、J/B/K、外部受信側契約 |
| CS11 | §2/§4 | schema/上限/失敗分類、秘密を記録しない証跡 |
| CS12 | §0/§7/§9 | local認可/別承認/正当session化の全gate |

元N01–N37は全て継承。追加表で独立行にしていないN06（現false後の旧active）は§4/§5のD優先・旧Q拒否、N15（Q番号を観測順へ転用）は§1/§9、N17（falseの意味拡張）は§4/§5の現対象限定を適用する。下記の追加negative/crash表は各行でN/T/CS参照を明記。特にN33のH制約非緩和、N34のR時計喪失、N35の全状態期限、N36/N37の両順序はLC21/22/26/27/28/29へ対応する。既存positive gateは全て閉鎖。

### 未確定gates（全て未解消、数値なし）

| Gate | 必要な根拠/決定 | 元gate | 現判定 |
| --- | --- | --- | --- |
| LG01 | 認証transactionのI/C/S/T/L/G/H由来と安全保管境界、実client/issuer適合 | G01/G02 | NO-GO |
| LG02 | 全writer/入口の排他、owner取得/交代/隔離、同一権威DB配置の実証 | G02 | NO-GO |
| LG03 | 永続commit耐久性、backup/restore/複製/ABA、非巻戻し根拠、旧owner排除 | G02 | NO-GO |
| LG04 | 失敗/不明commit時のC3全入口停止、closed起動/復旧、readback意味論 | G02/G05 | NO-GO |
| LG05 | Q/Xとtransport送信境界、Vとdispatchのrace、送信不明の取扱い | G02/G05 | NO-GO |
| LG06 | Delta_source/allowed/flight/apply、clock epoch/誤差/suspend/expiry/Retry方針 | G03 | NO-GO |
| LG07 | 応答schema/上限、ID非再使用/overflow、terminal保持/安全GC、失効範囲 | G02/G04 | NO-GO |
| LG08 | J/B/K、現在policy revision、同DB作用又は受信側fence/idempotency/共通順序、安全中断 | G05 | NO-GO |
| LG09 | 本契約の独立レビュー、別途offline実装scope/試験承認、nonce/PKCE/state/callback/cookie/CSRF/route/object scope | G06/G07 | NO-GO |

元のoffline状態遷移設計のレビュー受入れを維持する。今回、LG09の本契約の独立レビュー部分だけが完了した。別途offline実装scope/試験承認とnonce/PKCE/state/callback/cookie/CSRF/route/object scopeは未解消であり、LG09全体もNO-GOのまま。LGが未解消でも本資料の受入れは文書設計に限定され、C→allow/SessionSnapshotの経路は定義しない。


### 追加negative/crash順序表（42行、未実行）

設計レビュー用。42行は試験passでも網羅性証明でもない。元N01–N37を置換せず追加の切断点を示す。全行allow出力なし。C3/readinessは別の運用制約で7状態追加ではない。

| ID | 順序点 | 切断点/競合 | 必須結果 | 元遷移 | 元negative | 条件 |
| --- | --- | --- | --- | --- | --- | --- |
| LC01 | LS1 | 別T/L/G/Hで開始 | 束縛拒否。由来を文字列で補完しない | T01/T02 | N02/N03/N04 | CS02/CS03/CS04/CS05/CS06 |
| LC02 | LS1 | 同vで2writerがQ開始 | 高々一方成立。排他証明なしはC3停止。2つを現Qにしない | T02/T03/T18 | N14/N27 | CS06/CS09 |
| LC03 | LS1 | 開始commit前の確定失敗 | 新Q成立としない。利用禁止/必要なC3処理。自動再送権なし | T18 | N27 | CS09/CS11 |
| LC04 | LS1/LS6 | 開始commit成功不明 | closed/readback。matchedでも送信権なし | T15/T18 | N20/N27 | CS08/CS09 |
| LC05 | LS1/LS6 | 開始commit後・送信前crash | 保存Fから自動dispatchしない。旧受付閉鎖/候補破棄、T08条件が満たされる場合だけ別Qを検討 | T15/T08 | N12/N20 | CS08/CS09 |
| LC06 | LS1/LS3 | dispatch check後にV、その後transport送信 | V後未送信保証を主張しない。旧結果拒否。強い送信保証が必要ならNO-GO | T09/T06 | N05/N22 | CS07/CS09/CS10 |
| LC07 | LS2/LS3 | active反映Aの後V | Cが存在してもVでD/閉鎖/無効。許可出力なし | T04/T09/T17 | N05/N22 | CS07/CS09/CS10 |
| LC08 | LS2/LS3 | Vの後active反映を試行 | 現v/f/terminal比較で拒否、D維持 | T09/T06 | N05 | CS07/CS09 |
| LC09 | LS2 | 同Qの重複/readback/待機者配布 | 元m0/m1を保持、freshness更新不可 | T06 | N13 | CS08/CS09 |
| LC10 | LS2 | response commit成功直後にack喪失 | 保存結果不明。readbackは保存証明のみ、候補再発行なし | T18/T06 | N13/N27 | CS08/CS09/CS11 |
| LC11 | LS2 | timeout後の旧active/false | 旧Q/Eで現状態変更不可。falseも新Gへ適用しない | T07/T08/T06 | N12 | CS06/CS09 |
| LC12 | LS2 | 未認証/不明schema/型/上限/経路 | 現QはH、候補無効。成功boolに補完不可 | T07 | N16 | CS02/CS11 |
| LC13 | LS3 | D保存失敗/結果不明、stop flagも保存不能 | D永続済みと称さない。C3全入口停止条件が必要。条件なしは配置全体NO-GO | T09/T18 | N27 | CS07/CS09/CS10 |
| LC14 | LS4/LS2 | rotation開始commitの後旧Q false | 旧Q閉鎖済み、R/後続新Rを変えない | T10/T06 | N07 | CS06/CS09 |
| LC15 | LS2/LS4 | 現Q false commitの後rotation開始 | Dで開始拒否 | T05/T10 | N08 | CS07/CS09 |
| LC16 | LS4/LS6 | rotation intent commit前確定失敗 | R開始成立としない。送信なしを別途証明、勝手なretryなし | T18 | N27/N31 | CS09/CS11 |
| LC17 | LS4/LS6 | intent commit後・送信直前crash | 保存R/Xは送信権でない。未送信確証なしならH/再認証必須、同G巻戻しなし | T15/T12 | N10/N20/N31 | CS07/CS09 |
| LC18 | LS4/LS6 | 送信直後・応答前crash/timeout | provider処理不明。H/未解決X/閉鎖/再認証必須、自動再送なし | T12/T15 | N10/N31 | CS07/CS09 |
| LC19 | LS4/LS6 | provider成功後・local結果commit前crash | provider発行可能性とlocal不採用を分ける。H制約、旧H復活不可 | T12/T15/T13 | N10/N34 | CS07/CS09 |
| LC20 | LS4/LS6 | 結果commit成功後ack喪失 | readbackが新H/R保存を示しても新送信/許可/鮮度なし。restart時候補無効、未解決結果の制約を勝手に解除しない | T18/T15/T13 | N09/N20/N34 | CS08/CS09 |
| LC21 | LS4 | T12の明確失敗後に時計/通信回復 | Hの再認証必須保持、T08禁止 | T12/T08 | N10/N33 | CS07/CS09 |
| LC22 | LS4 | Rでclock epoch喪失後に成功遅着 | H/未解決X/閉鎖/再認証必須、遅い成功拒否 | T15/T13 | N34 | CS08/CS09 |
| LC23 | LS3/LS4 | Vの後rotation成功 | D維持、結果不採用。remote cleanupを勝手に実行しない | T09/T13 | N11 | CS07/CS10 |
| LC24 | LS4 | X1受理後X2受理、遅れてX1重複 | 旧Xは現H/Rを戻さない。未解決X1でX2開始は禁止 | T11/T13 | N09 | CS06/CS09 |
| LC25 | LS2/LS3 | Fで現対象確定期限を過ぎactive受信 | T16優先D。clock/期限が不明ならH、期限前と補完不可 | T04/T16/T15 | N21 | CS08 |
| LC26 | LS3 | W/F/R/Hで現G/session確定期限 | D/受付閉鎖。Rなら遅い結果採用不可 | T16/T13 | N35 | CS07/CS08/CS09 |
| LC27 | LS3/LS4 | Rで旧H/R期限終端commitが成功取込より先 | D、遅い成功拒否。取込transactionでも期限を先検査 | T16/T11/T13 | N36 | CS08/CS09 |
| LC28 | LS4/LS3 | 期限前成功取込が旧H/R期限eventより先 | 旧対象event破棄。現G/session期限ならD | T11/T16 | N37 | CS06/CS08/CS09 |
| LC29 | LS4 | Rで期限/clock対応が不明 | H/閉鎖/再認証必須。新H採用不可 | T15/T16/T13 | N21/N34 | CS08/CS09 |
| LC30 | LS6 | restartで保存C・旧clock epochをロード | 候補破棄/旧受付閉鎖、epoch間の時刻転記不可 | T15 | N20 | CS08/CS09 |
| LC31 | LS6 | DB backup復元/複製/ABAが検知不能 | closed維持、配置NO-GO。新認証だけでは旧owner/コピー排除の代用不可 | T18/T14 | N27/N28 | CS07/CS09/CS10 |
| LC32 | LS6 | GCでDを消去後旧callback到着 | 安全な非復活証明なしのGCは不可。ID再使用/旧G復活禁止 | T06/T14/T18 | N03/N28 | CS06/CS07/CS09 |
| LC33 | LS6 | readback matchedだが別owner/現在fence不明 | 保存証明だけ。owner/送信権を与えずclosed維持 | T18/T15 | N27 | CS09/CS10 |
| LC34 | LS6 | readback missing/conflict/unknown | 自動再送/ID再使用/旧C fallbackなし、原因制約保持 | T18/T15 | N20/N27/N31 | CS08/CS09/CS11 |
| LC35 | LS5 | Jの後B前にV | bool/outbox/dispatch checkだけでは不足、共通順序保証なければNO-GO | T09/T17 | N22 | CS10 |
| LC36 | LS5 | Bの後K前にV | 操作固有安全中断契約のみ。process kill/SQL rollbackを外部rollbackにしない | T17 | N23 | CS10 |
| LC37 | LS5 | Kの後V | 遡及取消なし、後続停止。補償は別承認 | T17 | N24 | CS10 |
| LC38 | LS5 | 外部receiverはidempotencyだけ/fence未検査 | 重複抑止は失効順序保証でない、NO-GO | T17 | N22/N23 | CS10/CS12 |
| LC39 | LS2/LS5 | provider O後失効/二段読取の間に変更 | 瞬時失効/atomic観測を主張しない。source lag未確定gate閉鎖 | T04/T17 | N25/N26 | CS08/CS10 |
| LC40 | LS2/LS5 | TTLをtoken寿命等から転用、receiptのみ更新 | 鮮度証明不成立、candidate利用/allow拒否 | T04/T16/T17 | N18/N19 | CS08 |
| LC41 | LS1/LS5 | identity/activeからgrant/sessionを生成 | 全工程拒否。由来・状態・local認可は独立 | T01/T17 | N01/N30/N32 | CS01/CS04/CS12 |
| LC42 | LS6 | 新T/Gだが適用失効/owner復旧制約が残る | 新認証だけでは再開不可、制約解消を推測しない | T14/T18 | N28/N29 | CS05/CS07/CS09 |
