```
���̕��͂́uTransport Layer Security (TLS) Application-Layer Protocol Negotiation Extension)�v�̓��{���ł��B
���̖|��̐��m���͕ۏ؂���܂���B���̎d�l�̌����ȕ��͉͂p��łł���A���̓��{���͌����̂��̂ł͂���܂���B


���J��:		2015-
�X�V��:		2015-
�|���:		Daiki Aminaka <1991.daiki@gmail.com>
```


    Internet Engineering Task Force (IETF)					�ҏW�@S.Friedl  Cisco Systems, Inc.
    Request for Comments: 7301		 			 	  			  A. Popov  Microsoft Corp.
    ����: Standards Track										  A. Langley  Google Inc.
    ISSN: 2070-1721												  E. Stephan  Orange
	      													���s  2014�N7��


-----


#Transport Layer Security (TLS)
#Application-Layer Protocol Negotiation Extension

### �T�v
���̎d�l��TLS�n���h�V�F�C�N��ōs����A�v���P�[�V�����w�̃v���g�R���l�S�V�G�[�V�����̂��߂�TLS�g����������܂��B
�Ⴆ��TCP��������UDP�̓���|�[�g�ŁA�����̃A�v���P�[�V�����v���g�R�����T�|�[�g����ꍇ�A���̊g����TLS�R�l�N�V������ʂ��Ďg�p�����v���g�R���̌����\�ɂ��܂��B

### ���̃����̈ʒu�t��
����́AInternet Standards Track�����ł���B
���̕����́AIETF�ɂ�鐬�ʕ��ł���AIETF�R�~���j�e�B�̍��ӂ�\��������̂ł���B����́A���J�̕]�����󂯁AIESG���甭�s�����F���ꂽ���̂ł���BInternet�W���ɂ��Ă̍X�Ȃ����[RFC5741 2��](https://tools.ietf.org/html/rfc5741#section-2)�ɂ݂���B


���̕����̌��݂̈ʒu�t���A����\�A�t�B�[�h�o�b�N�̕��@�ɂ��Ă̏��́A[http://www.rfc-editor.org/info/rfc7301](http://www.rfc-editor.org/info/rfc7301)���瓾����B


###���쌠�\��
Copyright (c) 2014 IETF Trust and the persons identified as the document authors.  All rights reserved.

This document is subject to [BCP 78](https://tools.ietf.org/html/bcp78) and the IETF Trust's Legal
Provisions Relating to IETF Documents ([http://trustee.ietf.org/license-info](http://trustee.ietf.org/license-info)) in effect on the date of
publication of this document.  Please review these documents
carefully, as they describe your rights and restrictions with respect
to this document.  Code Components extracted from this document must
include Simplified BSD License text as described in [Section 4](#design).e of
the Trust Legal Provisions and are provided without warranty as
described in the Simplified BSD License.

##�ڎ�

##### [1](#intro).����
##### [2](#req-language).�p��
##### [3](#ALPN).�A�v���P�[�V�����w�v���g�R������
###### [3.1](#ALPN-E).�A�v���P�[�V�����w�v���g�R�����g��
###### [3.2](#pro-selection).�v���g�R���̑I��
##### [4](#design).�f�U�C���̍l��
##### [5](#security).�Z�L�����e�B�̍l��
##### [6](#IANA).IANA�̍l��
##### [7](#acknowledge).�ӎ�
##### [8](#reference).�Q�l����
###### [8.1](#normative-ref).���p����
###### [8.2](#informative-ref).�Q�l����

##<a name = "intro"> 1</a>.����
TLS�v���g�R��[RFC5246](https://tools.ietf.org/html/rfc5246)�͂܂��܂��A�v���P�[�V�����w�̃v���g�R�������Ă���B
���̓���́A�A�v���P�[�V������443�ԃ|�[�g�ɑ��݂��鉼�z�I�ɂ��ׂẴO���[�o��IP��𒴂������S�Ȍo�H���g�p�\�ɂ���B

��̃T�[�o���|�[�g(�Ⴆ��443��)�ɂĕ����̃A�v���P�[�V�����v���g�R�����T�|�[�g����Ă��鎞�A�N���C�A���g�ƃT�[�o�̓R�l�N�V�������ƂɎg�p����A�v���P�[�V�����v���g�R����������K�v������B
���ꂼ��̃��E���h�g���b�v���G���h���[�U�̌o����������悤�ɁA�N���C�A���g-�T�[�o�Ԃ̃l�b�g���[�N���E���h�g���b�v�������邱�ƂȂ��A���̌����������邱�Ƃ��D�܂����B
����ɂ���͑I�΂ꂽ�A�v���P�[�V�����v���g�R���Ɋ�Â����ؖ����I�����\�ɂ��鎖�ɗL�v���낤�B

���̕����̓A�v���P�[�V�����w��TLS�n���h�V�F�C�N��Ńv���g�R���̑I�����\�ɂ���g�����������B
���̓�����HTTPbis WG�ɂāATLS���HTTP2([[HTTP2](#http2)])�̎g�p���Ɏ��g�ނ��߂ɗv�����ꂽ���Ƃł���B
�������Ȃ���AALPN�͔C�ӂ̃A�v���P�[�V�����w�̃v���g�R������e�Ղɂ���B

ALPN�ł́A�N���C�A���g�̓T�|�[�g����A�v���P�[�V�����v���g�R���̃��X�g��TLS��ClientHello���b�Z�[�W�̈ꕔ�Ƃ��đ��M����B
�T�[�o�̓v���g�R�����P�I�сATLS��ServerHello���b�Z�[�W�̈ꕔ�Ƃ��đ��M����B
�A�v���P�[�V�����v���g�R���̌��͂��̂悤��TLS�n���h�V�F�C�N��ŁA�l�b�g���[�N���E���h�g���b�v��ǉ����邱�Ɩ������������B�����Ă��̌��́A(�v���������)�T�[�o�ɂ��ꂼ��̃v���g�R���ƕʁX�̏ؖ�����Ή��t�������鎖���\�B

##<a name ="req-language"> 2</a>.�p��
���̕��͂ɂ����āA�L�[���[�h"MUST"�A"MUST NOT"�A"REQUIRED"�A"SHALL"�A"SHALL NOT"�A"SHOULD"�A"SHOULD NOT"�A"RECOMMENDED"�A"MAY"�A������ "OPTIONAL"��[RFC2119](https://tools.ietf.org/html/rfc2119)�ɕ\�L�����悤�ɉ��߂����B

##<a name ="ALPN"> 3</a>.�A�v���P�[�V�����w�v���g�R������
###<a name ="ALPN-E"> 3.1</a>. �A�v���P�[�V�����w�v���g�R�����g��
`("application_layer_protocol(16)")`�^�̐V�����g������`����A�N���C�A���g����"ClientHello"���b�Z�[�W�Ɋ܂܂�Ă��ǂ�(MAY)�B


    enum {
        application_layer_protocol_negotiation(16), (65536)
    } ExtentionType;


`("application_layer_protocol_negotiation(16)")`�g����`"extension_data"`�̈��`"ProtocolNameList"`�̒l���܂�(SHALL)�B


`opaque ProtocolName<1..2^8-1>;`


    struct {
        ProtocolName protocol_name_list<2..2^16-1>
    } ProtocolNameList;


`"ProtocolNameList"`�̓N���C�A���g���獐�m���ꂽ�D�݂̍~���̃v���g�R���̃��X�g���܂ށB
�v���g�R����[�U��](#IANA)("IANA�̍l��")�ɂďڍׂɐ�������Ă���悤�ɁAIANA-registered�ɂ����Ė��O�t�����A�s���ĂŁA��łȂ��o�C�g������ł���B
��̕�����͊܂܂��ׂ��łȂ��A����Ƀo�C�g������͐؂�l�߂���ׂ��łȂ��B

`"application_layer_protocol_nagotiation"`�g�����܂�ClientHello���󂯎��T�[�o�́A�K�؂ɑI�΂ꂽ�v���g�R�����܂މ�����Ԃ��ėǂ�(MAY)�B
�T�[�o�͔F���ł��Ȃ��v���g�R�����𖳎�����B
`("application_layer_protocol_negotiation(16)")`�^��ServerHello�g���͊g�����ꂽServerHello�Ɋ܂܂�ăN���C�A���g�ɕԂ���Ă��ǂ�(MAY)�B
`"ProtocolNameList"`�͊m���Ɉ��`"ProtocolName"`���܂܂Ȃ���΂Ȃ�Ȃ�(MUST)���Ƃ������A`("application_layer_protocol_nagotiation(16)")`�g����`"extension_data"`�̈�͏�Lclient��`"extension_data"`�Ɠ��l�ɍ\�������B


�]���āAClientHello��ServerHello���b�Z�[�W����`"application_layer_protocol_nagotiation"`�g���������S�ȃn���h�V�F�C�N�͎��̗�����s��([[RFC5246]7.3��](https://tools.ietf.org/html/rfc5246#section-7.3)�ƑΏƓI��)


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

*�̓I�v�V�����������͏󋵂ɂ�郁�b�Z�[�W�ł���A��ɑ�����킯�ł͂Ȃ��B


`"application_layer_protocol_negotiation"`�g���͏ȗ����ꂽ�n���h�V�F�C�N���̂悤�ɂȂ�B

    Client															Server
    
    ClientHello								-------->		ServerHello
    (ALPN extension & list of protocols)					(ALPN extension & selected protocol)
    
    														[ChangeCipherSpec]
    										<--------		Finished
    [ChangeCipherSpec]
    Finished								-------->
    
    Application Data						<------->		Application Data
    
    								Figure 2


�ق�������TLS�g���ƈႢ�A����̓R�l�N�V���������̃Z�b�V�����̃v���p�e�B���m�����Ȃ��B
�Z�b�V�����̍ĊJ�������̓Z�b�V�����`�P�b�g[RFC5077](https://tools.ietf.org/html/rfc5077)���p����ꂽ���A���̊g���̈ȑO�̃R���e���c�͕s�K�؂ł���B
�����ĐV���ȃn���h�V�F�C�N���b�Z�[�W�̒l�݂̂��l�������


###<a name ="pro-selection"> 3.2</a>. �v���g�R���̑I��
�T�[�o�͗D�揇�ŃT�|�[�g����v���g�R���̃��X�g�������Ƃ����҂���A�N���C�A���g���T�|�[�g����1�̃v���g�R�����I�΂��B
���̏ꍇ�A�T�[�o�̓N���C�A���g����񎦂��ꂽ���X�g�̒��ŃT�|�[�g�����ԗD��x�̍����v���g�R����I������ׂ��ł���(SHOULD)�B
�N���C�A���g���񎦂����v���g�R�����T�[�o��1���T�|�[�g���Ȃ��ꍇ�A�T�[�o��`"no_application_protocol"`�̃t�F�C�^���A���[�g�ŉ�������(SHALL)�B


    enum {
        no_application_protocol(120),
        (255)
    } AlertDescription;


ServerHello����`"application_layer_protocol_negotiation"`�g���^�C�v�ɂ���֌W�����v���g�R���͍Ăь������܂ŃR�l�N�V�����ň�ԐM���ł���(SHALL)�B
�T�[�o�͑I�����ꂽ�v���g�R���ɉ������Ȃ����A��ɃA�v���P�[�V�����f�[�^�̌����ɈႤ�v���g�R�����g�����Ƃ��Ȃ�(SHALL NOT)�B


##<a name ="design"> 4</a>. �f�U�C���̍l��
ALPN�g����TLS�v���g�R���g���̑�\�I�ȃf�U�C���ɒǏ]����悤�Ӑ}����Ă���B
���ɁA���͊m�����ꂽTLS�A�[�L�e�N�`���ɏ]�����N���C�A���g/�T�[�o��hello�������Ŋ��S�ɍs����B
`"appliation_layer_protocol_negotiation"`��ServerHello�g���́i�R�l�N�V�������Č������܂Łj�R�l�N�V�����Ɉ�ԐM���ł�����̂Ƃ���ATCP��������UDP�|�[�g�ԍ������̃R�l�N�V������ŗp������A�v���P�[�V�����w�v���g�R���ň�ԐM���ł��Ȃ����ɁA�l�b�g���[�N�v�f���R�l�N�V�����ɋ�ʂ��ꂽ�T�[�r�X��񋟂��邱�Ƃ��������߂Ƀv���[���e�L�X�g�ő�����B
�v���g�R���I���̏��L�����T�[�o�ɒu�����ƂŁAALPN�͏ؖ��I���������̓R�l�N�V�������[�e�B���O�������ꂽ�v���g�R���ɂ��V�i���I���~���ɂ���B


�ŏI�I�ɁA�n���h�V�F�C�N�̈ꕔ�Ƃ��ĕ����Ńv���g�R���I�����s�����ƂŁAALPN�R�l�N�V�����̊m���ɐ旧���Č����ꂽ�v���g�R���̉B���\�͂Ɋւ��č����Ȃ����M��������鎖�������B
�����v���g�R���̉B�����K�v�ł���΁A�^��TLS�Z�L�����e�B�ۏ؂ׂ̈ɃR�l�N�V�����m���̌�ɍČ�����̂��D�܂����菇���낤�B


##<a name ="security"> 5</a>. �Z�L�����e�B�̍l��
ALPN�g����TLS�̃Z�b�V�����m���������̓A�v���P�[�V�����f�[�^�̌����ɃZ�L�����e�B�ɉe����^���Ȃ��B
ALPN��TLS�R�l�N�V�����ƌ��ѕt����ꂽ�A�v���P�[�V�����w�v���g�R���̊O�I�ȉ��}�[�N��񋟂���������ʂ����B
���j�I�ɁA�R�l�N�V�����ƌ��ѕt����ꂽ�A�v���P�[�V�����w�v���g�R����TCP��������UDP�Ŏg����|�[�g�ԍ�����m���߂��邾�낤�B


�V���ȃv���g�R�����ʎq�������A�v���g�R�����ʎq���W�X�g�����g���������̎����҂ƃh�L�������g��v�W�҂́ATLS1.2�ȉ��ł̓N���C�A���g�������ł��̎��ʎq�𑗂鎖���l������ׂ����B
�܂��A�Œ�ł���10�N�قǂ̓u���E�U���ŏ���ClientHello�ł���瑁����TLS�𕁒ʂɎg�������l�����ׂ����B


���̂悤�Ȏ��ʎq���l�����ł������R�炷��������Ȃ����A�������͂��̏��R�k�̉\�������鎯�ʎq���l�̓���������N�������A�ɔ�̏���R�炷���A���ӂ������Ȃ���΂Ȃ�Ȃ��B
�������̂悤�Ȏ��ʎq�����̐V�����v���g�R�����ʎq�����p����Ȃ�A���̎��ʎq�͕����œǂ߂邩������Ȃ�TLS�̐ݒ�Ŏg����ׂ��łȂ�(SHOULD NOT)�B
�����Ă��̂悤�ȃv���g�R�����ʎq�ɂ��ďq�ׂĂ��镶�͂͂��̂悤�Ȉ��S�łȂ��d�l��񐄏����ׂ��ł���(SHOULD)�B


##<a name ="IANA"> 6</a>. IANA�̍l��
IANA��"ExtensionType Values"���W�X�g���͎��̃G���g�����܂߂邽�߂ɃA�b�v�f�[�g�����B


    16 application_layer_protocol_negotiation


���̕��͂�"Transport Layer Security (TLS) Extensions"�Ƃ����^�C�g�������݂��錳�ŁA"Application-Layer Protocol Negotiation (ALPN) Protocl IDs"�ƃ^�C�g���̕t�����v���g�R�����ʎq�̃��W�X�g�����m�������B


���̃��W�X�g���ɂ���G���g���͎��̗̈��K�v�Ƃ���B


* Protocl: �v���g�R����
* Identification Sequence: �v���g�R�������ʂ��鐳�m�ȃI�N�e�b�g�̒l�̏W���B����̓v���g�R������UTF-8�G���R�[�f�B���O[RFC3629](https://tools.ietf.org/html/rfc3629)��������Ȃ��B
* Reference: ���̃v���g�R�����`����d�l�ւ̎Q��


���̃��W�X�g����[RFC5226](https://tools.ietf.org/html/rfc5226)�ɒ�`����Ă���悤��"Expert Review"�|���V�[�̌��ŋ@�\���Ă���B
�w�����ꂽ�G�L�X�p�[�g�́A����̃v���g�R���̌݊����̂�������̊J�����\�ɂ���A�i�v�ŊȒP�Ɏ�ɓ���d�l�ւ̎Q�Ƃ̊ܗL�����߂�悤���ӂ��󂯂Ă���B


���̃��W�X�g���ւ̗v�^�̍ŏ��̏W���͎��̂悤�ɂȂ�B


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


##<a name ="acknowledge"> 7</a>. �ӎ�
���̕����́ANext Protocol Negotiation (NPN)�g���̕��͂ɂƂ�킯���b���󂯁AAdam Langley�ƃV�X�R��Tom Wesselman�ACullen Jennings�Ƃ̋c�_�ɂ�获�M���ꂽ�B


##<a name ="reference"> 8</a>. �Q�l����
###<a name ="normative-ref"> 8.1</a>. ���p����
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


###<a name ="informative-ref"> 8.2</a>. �Q�l����
<a name ="http2">[HTTP2]</a>    Belshe, M., Peon, R., and M. Thomson, "Hypertext Transfer
              Protocol version 2", Work in Progress, June 2014.


[RFC5077]  Salowey, J., Zhou, H., Eronen, P., and H. Tschofenig,
              "Transport Layer Security (TLS) Session Resumption without
              Server-Side State", [RFC 5077](https://tools.ietf.org/html/rfc5077), January 2008.
			  

## 9. ���҂̘A����

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
   
