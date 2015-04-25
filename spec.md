#Transport Layer Security (TLS)
#Application-Layer Protocol Negotiation Extension

### �T�v
���̎d�l��TLS�n���h�V�F�C�N��ōs����A�v���P�[�V�����w�̃v���g�R���l�S�V�G�[�V�����̂��߂�TLS�g����������܂��B
�Ⴆ��TCP��������UDP�̓���|�[�g�ŁA�����̃A�v���P�[�V�����v���g�R�����T�|�[�g����ꍇ�A���̊g����TLS�R�l�N�V������ʂ��Ďg�p�����v���g�R���̌����\�ɂ��܂��B

### ���̃����̈ʒu�t��
����́AInternet Standards Track�����ł���B
���̕����́AIETF�ɂ�鐬�ʕ��ł���AIETF�R�~���j�e�B�̍��ӂ�\��������̂ł���B����́A���J�̕]�����󂯁AIESG���甭�s�����F���ꂽ���̂ł���BInternet�W���ɂ��Ă̍X�Ȃ����RFC5741 2�߂ɂ݂���B


���̕����̌��݂̈ʒu�t���A����\�A�t�B�[�h�o�b�N�̕��@�ɂ��Ă̏��́Ahttp://www.rfc-editor.org/info/rfc7301���瓾����B


###���쌠�̍��m

##�ڎ�

### 1.����
### 2.�p��
### 3.�A�v���P�[�V�����w�v���g�R������
#### 3.1.�A�v���P�[�V�����w�v���g�R�����g��
#### 3.2.�v���g�R���̑I��
### 4.�f�U�C���̍l��
### 5.�Z�L�����e�B�̍l��
### 6.IANA�̍l��
### 7.�ӎ�
### 8.�Q�l����
#### 8.1.���p����
#### 8.2.�Q�l����

## 1.����
TLS�v���g�R���͂܂��܂��A�v���P�[�V�����w�̃v���g�R�������Ă��� (�����N�I�I)
���̓���́A�H�H�H443�ԃ|�[�g�ɂ��łɑ��݂���A�v���P�[�V�����Ɉ��S�Ȍo�H���g�p�\�ɂ���B


��̃T�[�o���|�[�g(�Ⴆ��443��)�ɂĕ����̃A�v���P�[�V�����v���g�R�����T�|�[�g����Ă��鎞�A�N���C�A���g�ƃT�[�o�̓R�l�N�V�������ƂɎg�p����A�v���P�[�V�����v���g�R����������K�v������B
�N���C�A���g-�T�[�o�Ԃ̃l�b�g���[�N���E���h�g���b�v�����邱�ƂȂ��ɂ��̌����������邱�Ƃ��D�܂����B���ꂼ��̃��E���h�g���b�v�̓G���h���[�U��experience��������悤�ɁB
����ɂ���͑I�΂ꂽ�A�v���P�[�V�����v���g�R���Ɋ�Â����ؖ����I�����\�ɂ��鎖�ɗL�v���낤�B

���̕����̓A�v���P�[�V�����w��TLS�n���h�V�F�C�N��Ńv���g�R���̑I�����\�ɂ���g�����������B
���̓�����HTTPbis WG�ɂāATLS���HTTP2�̎g�p���Ɏ��g�ނ��߂ɗv�����ꂽ���Ƃł���B
�������Ȃ���AALPN�͔C�ӂ̃A�v���P�[�V�����w�̃v���g�R������e�Ղɂ���B

ALPN�ł́A�N���C�A���g�̓T�|�[�g����A�v���P�[�V�����v���g�R���̃��X�g��TLS��ClientHello���b�Z�[�W�̈ꕔ�Ƃ��đ��M����B
�T�[�o�̓v���g�R�����P�I�сATLS��ServerHello���b�Z�[�W�̈ꕔ�Ƃ��đ��M����B
�A�v���P�[�V�����v���g�R���̌��͂��̂悤��TLS�n���h�V�F�C�N��ŁA�l�b�g���[�N���E���h�g���b�v��ǉ����邱�Ɩ������������B�����Ă��̌��́A(�v���������)�T�[�o�ɂ��ꂼ��̃v���g�R���ƕʁX�̏ؖ�����Ή��t��������鎖���\�B

## 2.�p��
���̕��͂ɂ����āA�L�[���[�h"MUST"�A"MUST NOT"�A"REQUIRED"�A"SHALL"�A"SHALL NOT"�A"SHOULD"�A"SHOULD NOT"�A"RECOMMENDED"�A"MAY"�A������ "OPTIONAL"��RFC2119�ɕ\�L�����悤�ɉ��߂����B

## 3.�A�v���P�[�V�����w�v���g�R������
### 3.1. �A�v���P�[�V�����w�v���g�R�����g��
("application_layer_protocol(16)")�^�̐V�����g������`����A�N���C�A���g����"ClientHello"���b�Z�[�W�Ɋ܂܂�Ă��ǂ�(MAY)�B


enum {
	 application_layer_protocol_negotiation(16), (65536)
} ExtentionType;


("application_layer_protocol_negotiation(16)")�g����"extension_data"�̈��"ProtocolNameList"�̒l���܂�(SHALL)�B


opaque ProtocolName<1..2^8-1>;


struct {
	   ProtocolName protocol_name_list<2..2^16-1>
} ProtocolNameList;


"ProtocolNameList"�̓N���C�A���g���獐�m���ꂽ�v���g�R���̃��X�g(�D�݂̍~���H)���܂ށB
�v���g�R����Section 6("IANA Consideratoin")�ɂďڍׂɐ�������Ă���悤�ɁAIANA-registered�ɂ����Ė��O�t�����Aopaque�ŋ�łȂ��o�C�g������ł���B
��̕�����͊܂܂��ׂ��łȂ��A����Ƀo�C�g������͐؂�l�߂���ׂ��łȂ��B

"application_layer_protocol_nagotiation"�g�����܂�ClientHello���󂯎��T�[�o�́A�K�؂ɑI�΂ꂽ�v���g�R�����܂ރ��X�|���X��Ԃ��ėǂ�(MAY)�B
�T�[�o�͔F���ł��Ȃ��v���g�R�����𖳎�����B
("application_layer_protocol_negotiation(16)")�^��ServerHello�g���͊g�����ꂽServerHello�Ɋ܂܂�ăN���C�A���g�ɕԂ���Ă��ǂ�(MAY)�B
"ProtocolNameList"�͊m���Ɉ��"ProtocolName"���܂܂Ȃ���΂Ȃ�Ȃ�(MUST)���Ƃ������A("application_layer_protocol_nagotiation(16)")�g����"extension_data"�̈�͏�Lclient��"extension_data"�Ɠ��l�ɍ\�������B


�]���āAClientHello��ServerHello���b�Z�[�W����"application_layer_protocol_nagotiation"�g���������S�ȃn���h�V�F�C�N�͎��̗��������(Section 7.3�ƑΔ䂳���H�H)


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

*�̓I�v�V�����������͏󋵂ɂ�郁�b�Z�[�W�ł���A��ɑ�����킯�ł͂Ȃ��B

�ق�������TLS�g���ƈႢ�A����̓R�l�N�V�����̂݁H�H�Z�b�V�����̃v���p�e�B���m�����Ȃ��B
�Z�b�V�����̍ĊJ�������̓Z�b�V�����`�P�b�g�iRFC5077�j���p����ꂽ���A���̊g���̈ȑO�̃R���e���c�͖��Ӗ��ł���H
�����ĐV���ȃn���h�V�F�C�N���b�Z�[�W�̒l�݂̂��l�������


### 3.2. �v���g�R���̑I��
�T�[�o�͗D�揇�H�ŃT�|�[�g����v���g�R���̃��X�g�������Ƃ����҂���A�N���C�A���g���T�|�[�g����1�̃v���g�R�����I�΂��B
���̏ꍇ�A�T�[�o�̓N���C�A���g����񎦂��ꂽ���X�g�̒��ŃT�|�[�g�����ԗD��x�̍����v���g�R����I������ׂ��ł���(SHOULD)�B
�N���C�A���g���񎦂����v���g�R�����T�[�o��1���T�|�[�g���Ȃ��ꍇ�A�T�[�o��"no_application_protocol"�̃t�F�C�^���A���[�g�Ń��X�|���X����(SHALL)�B


venum {
	 no_application_protocol(120),
	 (255)
} AlertDescription;


ServerHello����"application_layer_protocol_negotiation"�g���^�C�v�ɂ���m�肵���H�v���g�R���͍Ăь������܂ŃR�l�N�V�����ň�ԐM���ł���(SHALL)�B
�T�[�o�͑I�����ꂽ�v���g�R���ɉ������Ȃ����A��ɃA�v���P�[�V�����f�[�^�̌����ɈႤ�v���g�R�����g�����Ƃ��Ȃ�(SHALL NOT)�B


## 4. �f�U�C���̍l��
ALPN�g����TLS�v���g�R���g���̑�\�I�ȃf�U�C���ɒǏ]����悤�Ӑ}����Ă���B
���ɁA���͊m�����ꂽTLS�A�[�L�e�N�`���ɏ]�����N���C�A���g/�T�[�o��hello�������Ŋ��S�ɍs����B
"appliation_layer_protocol_negotiation"��ServerHello�g���̓R�l�N�V�����Ɉ�ԐM���ł�����̂Ƃ���i�R�l�N�V�������Č������܂Łj�ATCP��������UDP�|�[�g�ԍ������̃R�l�N�V������ŗp������A�v���P�[�V�����w�v���g�R���ň�ԐM���ł��Ȃ����ɁA�l�b�g���[�N�v�f(elements�H)���R�l�N�V�����̋�ʂ��ꂽ�T�[�r�X��񋟂��邱�Ƃ������B
�v���g�R���I���̏��L�����T�[�o�ɒu�����ƂŁAALPN�͏ؖ��I���������̓R�l�N�V�������[�e�B���O�������ꂽ�v���g�R���Ɉ˂邩������Ȃ��V�i���I��e�ՁH�ɂ���


�ŏI�I�ɁA�n���h�V�F�C�N�̈ꕔ�Ƃ��ăv���g�R���I���𕽕��ōs�����ƂŁAALPN�R�l�N�V�����̊m���ɐ旧���Č����ꂽ�v���g�R���̉B���\�͂Ɋւ��Ă�false�ȐM�p��������鎖�������B�H
�����v���g�R���̉B�����K�v�ł���΁A�^��TLS�Z�L�����e�B�ۏ؂ׂ̈ɍČ����D�܂����菇���낤�B


## 5. �Z�L�����e�B�̍l��
ALPN�g����TLS�̃Z�b�V�����m���������̓A�v���P�[�V�����f�[�^�̌����ɃZ�L�����e�B�ɉe����^���Ȃ��B
ALPN��TLS�R�l�N�V�����ƌ��ѕt����ꂽ�A�v���P�[�V�����w�v���g�R���̊O�I�ȉ��}�[�N�H��񋟂���������ʂ����B
���j�I�ɁA�R�l�N�V�����ƌ��ѕt����ꂽ�A�v���P�[�V�����w�v���g�R����TCP��������UDP�Ŏg����|�[�g�ԍ�����m���߂��邾�낤�B


�V���ȃv���g�R�����ʎq�������A�v���g�R�����ʎq���W�X�g�����g���������̎����҂ƃh�L�������g��v�W�҂́ATLS1.2�ȉ��ł̓N���C�A���g�������ł��̎��ʎq�𑗂鎖���l������ׂ����B
�܂��A�Œ�ł���10�N�قǂ̓u���E�U���ŏ���ClientHello�ł���瑁����TLS�𕁒ʂɎg�������l�����ׂ����B


���̂悤�Ȏ��ʎq���l�����ł������R�炷��������Ȃ����A�������͂��̏��R�k�̉\�������鎯�ʎq���v���t�@�C�����O�H�������N�������A�ɔ�̏���R�炷���A���ӂ������Ȃ���΂Ȃ�Ȃ��B
�������̂悤�Ȏ��ʎq�����̐V�����v���g�R�����ʎq�����p����Ȃ�A���̎��ʎq�͕����œǂ߂邩������Ȃ�TLS�̐ݒ�Ŏg����ׂ��łȂ�(SHOULD NOT)�B
�����Ă��̂悤�ȃv���g�R�����ʎq�ɂ��ďq�ׂĂ��镶�͂͂��̂悤�Ȉ��S�łȂ��d�l��񐄏����ׂ��ł���(SHOULD)�B


## 6. IANA�̍l��
IANA��"ExtensionType Values"���W�X�g���͎��̃G���g�����܂߂邽�߂ɃA�b�v�f�[�g�����B


16 application_layer_protocol_negotiation


���̕��͂�"Transport Layer Security (TLS) Extensions"�Ƃ����^�C�g�������݂��錳�ŁA"Application-Layer Protocol Negotiation (ALPN) Protocl IDs"�ƃ^�C�g���̕t�����v���g�R�����ʎq�̃��W�X�g�����m�������B


���̃��W�X�g���ɂ���G���g���͎��̗̈��K�v�Ƃ���B


* Protocl: �v���g�R����
* Identification Sequence: �v���g�R�������ʂ��鐳�m�ȃI�N�e�b�g�̒l�̏W���B����̓v���g�R������UTF-8�G���R�[�f�B���O[RFC3629]��������Ȃ��B
* Reference: ���̃v���g�R�����`����d�l�ւ̎Q��


���̃��W�X�g����[RFC5226]�ɒ�`����Ă���悤��"Expert Review"�|���V�[�̌��ŋ@�\���Ă���B
�w�����ꂽ�G�L�X�p�[�g�́A����̃v���g�R���̌݊����̂���������J������@���^����A�i�v�ŊȒP�Ɏ�ɓ���d�l�ւ̎Q�Ƃ̊ܗL���������邽�߂ɃA�h�o�C�X���󂯂�B�H


���̃��W�X�g���ւ̗v�^�̍ŏ��̏W���͎��̂悤�ɂȂ�B


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


## 7. �ӎ�
���̕����́ANext Protocol Negotiation (NPN)�g���̕��͂ɂƂ�킯���b���󂯁AAdam Langley�ƃV�X�R��Tom Wesselman�ACullen Jennings�Ƃ̋c�_�ɂ�获�M���ꂽ�B


## 8. �Q�l����
### 8.1. ���p����

### 8.2. �Q�l����

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
   
