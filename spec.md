```
この文章は「Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension)」の日本語訳です。
この翻訳の正確性は保証されません。この仕様の公式な文章は英語版であり、この日本語訳は公式のものではありません。


公開日:		2015-
更新日:		2015-
翻訳者:		Daiki Aminaka <1991.daiki@gmail.com>
```


    Internet Engineering Task Force (IETF)					編集　S.Friedl  Cisco Systems, Inc.
    Request for Comments: 7301		 			 	  			  A. Popov  Microsoft Corp.
    分類: Standards Track										  A. Langley  Google Inc.
    ISSN: 2070-1721												  E. Stephan  Orange
	      													発行  2014年7月


-----


#Transport Layer Security (TLS)
#Application-Layer Protocol Negotiation Extension

### 概要
この仕様はTLSハンドシェイク上で行われるアプリケーション層のプロトコルネゴシエーションのためのTLS拡張を説明します。
例えばTCPもしくはUDPの同一ポートで、複数のアプリケーションプロトコルをサポートする場合、この拡張がTLSコネクションを通して使用されるプロトコルの交渉を可能にします。

### このメモの位置付け
これは、Internet Standards Track文書である。
この文書は、IETFによる成果物であり、IETFコミュニティの合意を表現するものである。それは、公開の評価を受け、IESGから発行が承認されたものである。Internet標準についての更なる情報は[RFC5741 2節](https://tools.ietf.org/html/rfc5741#section-2)にみられる。


この文書の現在の位置付け、正誤表、フィードバックの方法についての情報は、[http://www.rfc-editor.org/info/rfc7301](http://www.rfc-editor.org/info/rfc7301)から得られる。


###著作権表示
Copyright (c) 2014 IETF Trust and the persons identified as the document authors.  All rights reserved.

This document is subject to [BCP 78](https://tools.ietf.org/html/bcp78) and the IETF Trust's Legal
Provisions Relating to IETF Documents ([http://trustee.ietf.org/license-info](http://trustee.ietf.org/license-info)) in effect on the date of
publication of this document.  Please review these documents
carefully, as they describe your rights and restrictions with respect
to this document.  Code Components extracted from this document must
include Simplified BSD License text as described in [Section 4](#design).e of
the Trust Legal Provisions and are provided without warranty as
described in the Simplified BSD License.

##目次

##### [1](#intro).導入
##### [2](#req-language).用語
##### [3](#ALPN).アプリケーション層プロトコル交渉
###### [3.1](#ALPN-E).アプリケーション層プロトコル交渉拡張
###### [3.2](#pro-selection).プロトコルの選択
##### [4](#design).デザインの考慮
##### [5](#security).セキュリティの考慮
##### [6](#IANA).IANAの考慮
##### [7](#acknowledge).謝辞
##### [8](#reference).参考文献
###### [8.1](#normative-ref).引用文書
###### [8.2](#informative-ref).参考文書

##<a name = "intro"> 1</a>.導入
TLSプロトコル[RFC5246](https://tools.ietf.org/html/rfc5246)はますますアプリケーション層のプロトコルを内包している。
この内包は、アプリケーションに443番ポートに存在する仮想的にすべてのグローバルIP基板を超えた安全な経路を使用可能にする。

一つのサーバ側ポート(例えば443番)にて複数のアプリケーションプロトコルがサポートされている時、クライアントとサーバはコネクションごとに使用するアプリケーションプロトコルを交渉する必要がある。
それぞれのラウンドトリップがエンドユーザの経験を下げるように、クライアント-サーバ間のネットワークラウンドトリップを加えることなく、この交渉を完了することが好ましい。
さらにそれは選ばれたアプリケーションプロトコルに基づいた証明書選択を可能にする事に有益だろう。

この文書はアプリケーション層がTLSハンドシェイク上でプロトコルの選択を可能にする拡張を説明する。
この動きはHTTPbis WGにて、TLS上のHTTP2([[HTTP2](#http2)])の使用交渉に取り組むために要求されたことである。
しかしながら、ALPNは任意のアプリケーション層のプロトコル交渉を容易にする。

ALPNでは、クライアントはサポートするアプリケーションプロトコルのリストをTLSのClientHelloメッセージの一部として送信する。
サーバはプロトコルを１つ選び、TLSのServerHelloメッセージの一部として送信する。
アプリケーションプロトコルの交渉はこのようにTLSハンドシェイク上で、ネットワークラウンドトリップを追加すること無く完了される。そしてこの交渉は、(要求があれば)サーバにそれぞれのプロトコルと別々の証明書を対応付けさせる事が可能。

##<a name ="req-language"> 2</a>.用語
この文章において、キーワード"MUST"、"MUST NOT"、"REQUIRED"、"SHALL"、"SHALL NOT"、"SHOULD"、"SHOULD NOT"、"RECOMMENDED"、"MAY"、そして "OPTIONAL"は[RFC2119](https://tools.ietf.org/html/rfc2119)に表記されるように解釈される。

##<a name ="ALPN"> 3</a>.アプリケーション層プロトコル交渉
###<a name ="ALPN-E"> 3.1</a>. アプリケーション層プロトコル交渉拡張
`("application_layer_protocol(16)")`型の新しい拡張が定義され、クライアント側の"ClientHello"メッセージに含まれても良い(MAY)。


    enum {
        application_layer_protocol_negotiation(16), (65536)
    } ExtentionType;


`("application_layer_protocol_negotiation(16)")`拡張の`"extension_data"`領域は`"ProtocolNameList"`の値を含む(SHALL)。


`opaque ProtocolName<1..2^8-1>;`


    struct {
        ProtocolName protocol_name_list<2..2^16-1>
    } ProtocolNameList;


`"ProtocolNameList"`はクライアントから告知された好みの降順のプロトコルのリストを含む。
プロトコルは[６節](#IANA)("IANAの考慮")にて詳細に説明されているように、IANA-registeredにおいて名前付けられ、不明瞭で、空でないバイト文字列である。
空の文字列は含まれるべきでなく、さらにバイト文字列は切り詰められるべきでない。

`"application_layer_protocol_nagotiation"`拡張を含むClientHelloを受け取るサーバは、適切に選ばれたプロトコルを含む応答を返して良い(MAY)。
サーバは認識できないプロトコル名を無視する。
`("application_layer_protocol_negotiation(16)")`型のServerHello拡張は拡張されたServerHelloに含まれてクライアントに返されても良い(MAY)。
`"ProtocolNameList"`は確かに一つの`"ProtocolName"`を含まなければならない(MUST)ことを除き、`("application_layer_protocol_nagotiation(16)")`拡張の`"extension_data"`領域は上記clientの`"extension_data"`と同様に構成される。


従って、ClientHelloとServerHelloメッセージ内の`"application_layer_protocol_nagotiation"`拡張を持つ完全なハンドシェイクは次の流れを行う([[RFC5246]7.3節](https://tools.ietf.org/html/rfc5246#section-7.3)と対照的に)


    Client															Server
	
    ClientHello								-------->		ServerHello
    (ALPN extension & list of protocols)					(ALPN extension & selected protocol)
    
    		  	   	  										Certificate*
    														ServerKeyExchange*
	    													CertificateRequese*
    										<--------		ServerHelloDone
    
    Certificate*
    ClientKeyExchange
    CertificateVerify*
    [ChangeCipherSpec]
    Finished								-------->
    														[ChangeCipherSpec]
    														Finished
    
    Application Data						<------->		Application Data
    
    								Figure 1

*はオプションもしくは状況によるメッセージであり、常に送られるわけではない。


`"application_layer_protocol_negotiation"`拡張は省略されたハンドシェイク次のようになる。

    Client															Server
    
    ClientHello								-------->		ServerHello
    (ALPN extension & list of protocols)					(ALPN extension & selected protocol)
    
    														[ChangeCipherSpec]
    										<--------		Finished
    [ChangeCipherSpec]
    Finished								-------->
    
    Application Data						<------->		Application Data
    
    								Figure 2


ほか多数のTLS拡張と違い、これはコネクションだけのセッションのプロパティを確立しない。
セッションの再開もしくはセッションチケット[RFC5077](https://tools.ietf.org/html/rfc5077)が用いられた時、この拡張の以前のコンテンツは不適切である。
そして新たなハンドシェイクメッセージの値のみが考慮される


###<a name ="pro-selection"> 3.2</a>. プロトコルの選択
サーバは優先順でサポートするプロトコルのリストを持つことを期待され、クライアントがサポートする1つのプロトコルが選ばれる。
その場合、サーバはクライアントから提示されたリストの中でサポートする一番優先度の高いプロトコルを選択するべきである(SHOULD)。
クライアントが提示したプロトコルをサーバが1つもサポートしない場合、サーバは`"no_application_protocol"`のフェイタルアラートで応答する(SHALL)。


    enum {
        no_application_protocol(120),
        (255)
    } AlertDescription;


ServerHello内の`"application_layer_protocol_negotiation"`拡張タイプにある関係したプロトコルは再び交渉されるまでコネクションで一番信頼できる(SHALL)。
サーバは選択されたプロトコルに応答しないし、後にアプリケーションデータの交換に違うプロトコルを使うこともない(SHALL NOT)。


##<a name ="design"> 4</a>. デザインの考慮
ALPN拡張はTLSプロトコル拡張の代表的なデザインに追従するよう意図されている。
特に、交渉は確立されたTLSアーキテクチャに従ったクライアント/サーバのhello交換内で完全に行われる。
`"appliation_layer_protocol_negotiation"`のServerHello拡張は（コネクションが再交渉されるまで）コネクションに一番信頼できるものとされ、TCPもしくはUDPポート番号がそのコネクション上で用いられるアプリケーション層プロトコルで一番信頼できない時に、ネットワーク要素がコネクションに区別されたサービスを提供することを許可すためにプレーンテキストで送られる。
プロトコル選択の所有権をサーバに置くことで、ALPNは証明選択もしくはコネクションルーティングが交渉されたプロトコルによるシナリオを円滑にする。


最終的に、ハンドシェイクの一部として平文でプロトコル選択を行うことで、ALPNコネクションの確立に先立って交渉されたプロトコルの隠蔽能力に関して根拠なき自信を取り入れる事を避ける。
もしプロトコルの隠蔽が必要であれば、真のTLSセキュリティ保証の為にコネクション確立の後に再交渉するのが好ましい手順だろう。


##<a name ="security"> 5</a>. セキュリティの考慮
ALPN拡張はTLSのセッション確立もしくはアプリケーションデータの交換にセキュリティに影響を与えない。
ALPNはTLSコネクションと結び付けられたアプリケーション層プロトコルの外的な可視マークを提供する役割を果たす。
歴史的に、コネクションと結び付けられたアプリケーション層プロトコルはTCPもしくはUDPで使われるポート番号から確かめられるだろう。


新たなプロトコル識別子を加え、プロトコル識別子レジストリを拡張するつもりの実装者とドキュメント編v集者は、TLS1.2以下ではクライアントが平文でその識別子を送る事を考慮するべきだ。
また、最低でも先10年ほどはブラウザが最初のClientHelloでこれら早期のTLSを普通に使う事を考慮すべきだ。


そのような識別子が個人を特定できる情報を漏らすかもしれない時、もしくはその情報漏洩の可能性がある識別子が個人の同定を引き起こすか、極秘の情報を漏らす時、注意が払われなければならない。
もしそのような識別子がこの新しいプロトコル識別子を応用するなら、その識別子は平文で読めるかもしれないTLSの設定で使われるべきでない(SHOULD NOT)。
そしてそのようなプロトコル識別子について述べている文章はそのような安全でない仕様を非推奨すべきである(SHOULD)。


##<a name ="IANA"> 6</a>. IANAの考慮
IANAは"ExtensionType Values"レジストリは次のエントリを含めるためにアップデートした。


    16 application_layer_protocol_negotiation


この文章は"Transport Layer Security (TLS) Extensions"というタイトルが存在する元で、"Application-Layer Protocol Negotiation (ALPN) Protocl IDs"とタイトルの付いたプロトコル識別子のレジストリを確立した。


このレジストリにあるエントリは次の領域を必要とする。


* Protocl: プロトコル名
* Identification Sequence: プロトコルを識別する正確なオクテットの値の集合。これはプロトコル名のUTF-8エンコーディング[RFC3629](https://tools.ietf.org/html/rfc3629)かもしれない。
* Reference: そのプロトコルを定義する仕様への参照


このレジストリは[RFC5226](https://tools.ietf.org/html/rfc5226)に定義されているように"Expert Review"ポリシーの元で機能している。
指名されたエキスパートは、特定のプロトコルの互換性のある実装の開発を可能にする、永久で簡単に手に入る仕様への参照の含有を勧めるよう注意を受けている。


このレジストリへの要録の最初の集合は次のようになる。


    Protocol: HTTP/1.1
    Identifidcation Sequence: 0x68 0x74 0x74 0x70 0x2f 0x31 0x2e 0x31 ("http/1.1")
    Reference: [RFC7230](https://tools.ietf.org/html/rfc7230)


    Protocol: SPDY/1
    Identifidcation Sequence: 0x73 0x70 0x64 0x79 0x2f 0x31 ("spdy/1")
    Reference: [http://dev.chromium.org/spdy/spdy-protocol/spdy-protocol-draft1](http://dev.chromium.org/spdy/spdy-protocol/spdy-protocol-draft1)


    Protocol:  SPDY/2
    Identification Sequence: 0x73 0x70 0x64 0x79 0x2f 0x32 ("spdy/2")
    Reference: [http://dev.chromium.org/spdy/spdy-protocol/spdy-protocol-draft2](http://dev.chromium.org/spdy/spdy-protocol/spdy-protocol-draft2)


    Protocol:  SPDY/3
    Identification Sequence: 0x73 0x70 0x64 0x79 0x2f 0x33 ("spdy/3")
    Reference: [http://dev.chromium.org/spdy/spdy-protocol/spdy-protocol-draft3](http://dev.chromium.org/spdy/spdy-protocol/spdy-protocol-draft3)


##<a name ="acknowledge"> 7</a>. 謝辞
この文書は、Next Protocol Negotiation (NPN)拡張の文章にとりわけ恩恵を受け、Adam LangleyとシスコのTom Wesselman、Cullen Jenningsとの議論により執筆された。


##<a name ="reference"> 8</a>. 参考文献
###<a name ="normative-ref"> 8.1</a>. 引用文書
[RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", [BCP 14](https://tools.ietf.org/html/bcp14), [RFC 2119](https://tools.ietf.org/html/rfc2119), March 1997.


 [RFC3629]  Yergeau, F., "UTF-8, a transformation format of ISO
              10646", STD 63, [RFC 3629](https://tools.ietf.org/html/rfc3629), November 2003.


[RFC5226]  Narten, T. and H. Alvestrand, "Guidelines for Writing an
              IANA Considerations Section in RFCs", [BCP 26](https://tools.ietf.org/html/bcp26), [RFC 5226](https://tools.ietf.org/html/rfc5226), May 2008.


[RFC5246]  Dierks, T. and E. Rescorla, "The Transport Layer Security
              (TLS) Protocol Version 1.2", [RFC 5246](https://tools.ietf.org/html/rfc5246), August 2008.


[RFC7230]  Fielding, R. and J. Reschke, "Hypertext Transfer Protocol
              (HTTP/1.1): Message Syntax and Routing", [RFC 7230](https://tools.ietf.org/html/rfc7230), June 2014.


###<a name ="informative-ref"> 8.2</a>. 参考文書
<a name ="http2">[HTTP2]</a>    Belshe, M., Peon, R., and M. Thomson, "Hypertext Transfer
              Protocol version 2", Work in Progress, June 2014.


[RFC5077]  Salowey, J., Zhou, H., Eronen, P., and H. Tschofenig,
              "Transport Layer Security (TLS) Session Resumption without
              Server-Side State", [RFC 5077](https://tools.ietf.org/html/rfc5077), January 2008.
			  

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
   
