#Transport Layer Security (TLS)
#Application-Layer Protocol Negotiation Extension

### 概要
この仕様はTLSハンドシェイク上で行われるアプリケーション層のプロトコルネゴシエーションのためのTLS拡張を説明します。
例えばTCPもしくはUDPの同一ポートで、複数のアプリケーションプロトコルをサポートする場合、この拡張がTLSコネクションを通して使用されるプロトコルの交渉を可能にします。

### このメモの位置付け
これは、Internet Standards Track文書である。
この文書は、IETFによる成果物であり、IETFコミュニティの合意を表現するものである。それは、公開の評価を受け、IESGから発行が承認されたものである。Internet標準についての更なる情報はRFC5741 2節にみられる。


この文書の現在の位置付け、正誤表、フィードバックの方法についての情報は、http://www.rfc-editor.org/info/rfc7301から得られる。


###著作権の告知

##目次

### 1.導入
### 2.用語
### 3.アプリケーション層プロトコル交渉
#### 3.1.アプリケーション層プロトコル交渉拡張
#### 3.2.プロトコルの選択
### 4.デザインの考慮
### 5.セキュリティの考慮
### 6.IANAの考慮
### 7.謝辞
### 8.参考文献
#### 8.1.引用文書
#### 8.2.参考文書

## 1.導入
TLSプロトコルはますますアプリケーション層のプロトコルを内包している (リンク！！)
この内包は、？？？443番ポートにすでに存在するアプリケーションに安全な経路を使用可能にする。


一つのサーバ側ポート(例えば443番)にて複数のアプリケーションプロトコルがサポートされている時、クライアントとサーバはコネクションごとに使用するアプリケーションプロトコルを交渉する必要がある。
クライアント-サーバ間のネットワークラウンドトリップ加えることなしにこの交渉を完了することが好ましい。それぞれのラウンドトリップはエンドユーザのexperienceを下げるように。
さらにそれは選ばれたアプリケーションプロトコルに基づいた証明書選択を可能にする事に有益だろう。

この文書はアプリケーション層がTLSハンドシェイク上でプロトコルの選択を可能にする拡張を説明する。
この動きはHTTPbis WGにて、TLS上のHTTP2の使用交渉に取り組むために要求されたことである。
しかしながら、ALPNは任意のアプリケーション層のプロトコル交渉を容易にする。

ALPNでは、クライアントはサポートするアプリケーションプロトコルのリストをTLSのClientHelloメッセージの一部として送信する。
サーバはプロトコルを１つ選び、TLSのServerHelloメッセージの一部として送信する。
アプリケーションプロトコルの交渉はこのようにTLSハンドシェイク上で、ネットワークラウンドトリップを追加すること無く完了される。そしてこの交渉は、(要求があれば)サーバにそれぞれのプロトコルと別々の証明書を対応付けさせるる事が可能。

## 2.用語
この文章において、キーワード"MUST"、"MUST NOT"、"REQUIRED"、"SHALL"、"SHALL NOT"、"SHOULD"、"SHOULD NOT"、"RECOMMENDED"、"MAY"、そして "OPTIONAL"はRFC2119に表記されるように解釈される。

## 3.アプリケーション層プロトコル交渉
### 3.1. アプリケーション層プロトコル交渉拡張
("application_layer_protocol(16)")型の新しい拡張が定義され、クライアント側の"ClientHello"メッセージに含まれても良い(MAY)。


enum {
	 application_layer_protocol_negotiation(16), (65536)
} ExtentionType;


("application_layer_protocol_negotiation(16)")拡張の"extension_data"領域は"ProtocolNameList"の値を含む(SHALL)。


opaque ProtocolName<1..2^8-1>;


struct {
	   ProtocolName protocol_name_list<2..2^16-1>
} ProtocolNameList;


"ProtocolNameList"はクライアントから告知されたプロトコルのリスト(好みの降順？)を含む。
プロトコルはSection 6("IANA Consideratoin")にて詳細に説明されているように、IANA-registeredにおいて名前付けられ、opaqueで空でないバイト文字列である。
空の文字列は含まれるべきでなく、さらにバイト文字列は切り詰められるべきでない。

"application_layer_protocol_nagotiation"拡張を含むClientHelloを受け取るサーバは、適切に選ばれたプロトコルを含むレスポンスを返して良い(MAY)。
サーバは認識できないプロトコル名を無視する。
("application_layer_protocol_negotiation(16)")型のServerHello拡張は拡張されたServerHelloに含まれてクライアントに返されても良い(MAY)。
"ProtocolNameList"は確かに一つの"ProtocolName"を含まなければならない(MUST)ことを除き、("application_layer_protocol_nagotiation(16)")拡張の"extension_data"領域は上記clientの"extension_data"と同様に構成される。


従って、ClientHelloとServerHelloメッセージ内の"application_layer_protocol_nagotiation"拡張を持つ完全なハンドシェイクは次の流れを持つ(Section 7.3と対比される？？)


Client																					Server

ClientHello												-------->						ServerHello
(ALPN extension & list of protocols)													(ALPN extension & selected protocol)

	  			  	   	  																Certificate*
																						ServerKeyExchange*
																						CertificateRequese*
														<--------						ServerHelloDone

Certificate*
ClientKeyExchange
CertificateVerify*
[ChangeCipherSpec]
Finished												-------->
																						[ChangeCipherSpec]
																						Finished

Application Data										<------->						Application Data

														Figure 1

*はオプションもしくは状況によるメッセージであり、常に送られるわけではない。

ほか多数のTLS拡張と違い、これはコネクションのみ？？セッションのプロパティを確立しない。
セッションの再開もしくはセッションチケット（RFC5077）が用いられた時、この拡張の以前のコンテンツは無意味である？
そして新たなハンドシェイクメッセージの値のみが考慮される


### 3.2. プロトコルの選択
サーバは優先順？でサポートするプロトコルのリストを持つことを期待され、クライアントがサポートする1つのプロトコルが選ばれる。
その場合、サーバはクライアントから提示されたリストの中でサポートする一番優先度の高いプロトコルを選択するべきである(SHOULD)。
クライアントが提示したプロトコルをサーバが1つもサポートしない場合、サーバは"no_application_protocol"のフェイタルアラートでレスポンスする(SHALL)。


venum {
	 no_application_protocol(120),
	 (255)
} AlertDescription;


ServerHello内の"application_layer_protocol_negotiation"拡張タイプにある確定した？プロトコルは再び交渉されるまでコネクションで一番信頼できる(SHALL)。
サーバは選択されたプロトコルに応答しないし、後にアプリケーションデータの交換に違うプロトコルを使うこともない(SHALL NOT)。


## 4. デザインの考慮
ALPN拡張はTLSプロトコル拡張の代表的なデザインに追従するよう意図されている。
特に、交渉は確立されたTLSアーキテクチャに従ったクライアント/サーバのhello交換内で完全に行われる。
"appliation_layer_protocol_negotiation"のServerHello拡張はコネクションに一番信頼できるものとされ（コネクションが再交渉されるまで）、TCPもしくはUDPポート番号がそのコネクション上で用いられるアプリケーション層プロトコルで一番信頼できない時に、ネットワーク要素(elements？)がコネクションの区別されたサービスを提供することを許す。
プロトコル選択の所有権をサーバに置くことで、ALPNは証明選択もしくはコネクションルーティングが交渉されたプロトコルに依るかもしれないシナリオを容易？にする


最終的に、ハンドシェイクの一部としてプロトコル選択を平文で行うことで、ALPNコネクションの確立に先立って交渉されたプロトコルの隠蔽能力に関してはfalseな信用を取り入れる事を避ける。？
もしプロトコルの隠蔽が必要であれば、真のTLSセキュリティ保証の為に再交渉が好ましい手順だろう。


## 5. セキュリティの考慮
ALPN拡張はTLSのセッション確立もしくはアプリケーションデータの交換にセキュリティに影響を与えない。
ALPNはTLSコネクションと結び付けられたアプリケーション層プロトコルの外的な可視マーク？を提供する役割を果たす。
歴史的に、コネクションと結び付けられたアプリケーション層プロトコルはTCPもしくはUDPで使われるポート番号から確かめられるだろう。


新たなプロトコル識別子を加え、プロトコル識別子レジストリを拡張するつもりの実装者とドキュメント編v集者は、TLS1.2以下ではクライアントが平文でその識別子を送る事を考慮するべきだ。
また、最低でも先10年ほどはブラウザが最初のClientHelloでこれら早期のTLSを普通に使う事を考慮すべきだ。


そのような識別子が個人を特定できる情報を漏らすかもしれない時、もしくはその情報漏洩の可能性がある識別子がプロファイリング？を引き起こすか、極秘の情報を漏らす時、注意が払われなければならない。
もしそのような識別子がこの新しいプロトコル識別子を応用するなら、その識別子は平文で読めるかもしれないTLSの設定で使われるべきでない(SHOULD NOT)。
そしてそのようなプロトコル識別子について述べている文章はそのような安全でない仕様を非推奨すべきである(SHOULD)。


## 6. IANAの考慮
IANAは"ExtensionType Values"レジストリは次のエントリを含めるためにアップデートした。


16 application_layer_protocol_negotiation


この文章は"Transport Layer Security (TLS) Extensions"というタイトルが存在する元で、"Application-Layer Protocol Negotiation (ALPN) Protocl IDs"とタイトルの付いたプロトコル識別子のレジストリを確立した。


このレジストリにあるエントリは次の領域を必要とする。


* Protocl: プロトコル名
* Identification Sequence: プロトコルを識別する正確なオクテットの値の集合。これはプロトコル名のUTF-8エンコーディング[RFC3629]かもしれない。
* Reference: そのプロトコルを定義する仕様への参照


このレジストリは[RFC5226]に定義されているように"Expert Review"ポリシーの元で機能している。
指名されたエキスパートは、特定のプロトコルの互換性のある実装を開発する機会を与える、永久で簡単に手に入る仕様への参照の含有を助成するためにアドバイスを受ける。？


このレジストリへの要録の最初の集合は次のようになる。


Protocol: HTTP/1.1
Identifidcation Sequence: 0x68 0x74 0x74 0x70 0x2f 0x31 0x2e 0x31 ("http/1.1")
Reference: [RFC7230]


Protocol: SPDY/1
Identifidcation Sequence: 0x73 0x70 0x64 0x79 0x2f 0x31 ("spdy/1")
Reference: http://dev.chromium.org/spdy/spdy-protocol/spdy-protocol-draft1


Protocol:  SPDY/2
Identification Sequence: 0x73 0x70 0x64 0x79 0x2f 0x32 ("spdy/2")
Reference: http://dev.chromium.org/spdy/spdy-protocol/spdy-protocol-draft2


Protocol:  SPDY/3
Identification Sequence: 0x73 0x70 0x64 0x79 0x2f 0x33 ("spdy/3")
Reference: http://dev.chromium.org/spdy/spdy-protocol/spdy-protocol-draft3


## 7. 謝辞
この文書は、Next Protocol Negotiation (NPN)拡張の文章にとりわけ恩恵を受け、Adam LangleyとシスコのTom Wesselman、Cullen Jenningsとの議論により執筆された。


## 8. 参考文献
### 8.1. 引用文書

### 8.2. 参考文書

## 9. 著者の連絡先

Stephan Friedl
Cisco Systems, Inc.
170 West Tasman Drive
San Jose, CA  95134
USA


Phone: (720)562-6785
EMail: sfriedl@cisco.com


Andrei Popov
Microsoft Corp.
One Microsoft Way
Redmond, WA  98052
USA


EMail: andreipo@microsoft.com


Adam Langley
Google Inc.
USA

EMail: agl@google.com


Emile Stephan
Orange
2 avenue Pierre Marzin
Lannion  F-22307
France

EMail: emile.stephan@orange.com
   
