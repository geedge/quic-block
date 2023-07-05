#include <iostream>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <string.h>
#include <inttypes.h>
#include <cmath>
#include <iomanip>
#include <cstring>
#include <sstream>
#include <vector>

#define QUIC_AES_128_KEY_LEN 16
#define QUIC_IV_LEN 12
#define QUIC_MAX_UDP_PAYLOAD_SIZE 65527

using namespace std;

///////////////////////////////////////////////////////////////////////////////
// 获取没有加密的QUIC包
///////////////////////////////////////////////////////////////////////////////

using namespace std;
void printByteStream(const vector<unsigned char> &byteStream)
{
    for (const auto &byte : byteStream)
    {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(byte) << " ";
    }
    cout << endl << endl;
}
vector<unsigned char> getAckFrame()
{
    return {0x02, 0x00, 0x00, 0x00, 0x00};
}
vector<unsigned char> concatenateByteStreams(const vector<vector<unsigned char>> &byteStreams)
{
    // 连接vector<unsigned char>，这个方法虽然可以复用，但是看着起来不直观
    vector<unsigned char> result;
    for (const auto &byteStream : byteStreams)
    {
        result.insert(result.end(), byteStream.begin(), byteStream.end());
    }
    return result;
}
vector<unsigned char> getLenBytes(const size_t length, int return_len)
{
    // return_len为0表示变长，其余值为指定长度
    // 输入一个字节流数据，返回它的长度，用字节流表示
    if (return_len == 0)
    { // 变长
        if (length < 64)
        {
            return {static_cast<unsigned char>(length)};
        }
        else if (length < 16383)
        {
            unsigned short len = length | 0x4000;
            return {static_cast<unsigned char>((len >> 8) & 0xFF), static_cast<unsigned char>(len & 0xFF)};
        }
        else if (length < 1073741823)
        {
            unsigned int len = length | 0x40000000;
            return {
                static_cast<unsigned char>((len >> 24) & 0xFF),
                static_cast<unsigned char>((len >> 16) & 0xFF),
                static_cast<unsigned char>((len >> 8) & 0xFF),
                static_cast<unsigned char>(len & 0xFF)};
        }
        else
        {
            unsigned long long len = length | 0x4000000000000000;
            return {
                static_cast<unsigned char>((len >> 56) & 0xFF),
                static_cast<unsigned char>((len >> 48) & 0xFF),
                static_cast<unsigned char>((len >> 40) & 0xFF),
                static_cast<unsigned char>((len >> 32) & 0xFF),
                static_cast<unsigned char>((len >> 24) & 0xFF),
                static_cast<unsigned char>((len >> 16) & 0xFF),
                static_cast<unsigned char>((len >> 8) & 0xFF),
                static_cast<unsigned char>(len & 0xFF)};
        }
    }
    else
    {
        vector<unsigned char> lengthBytes;
        for (int i = return_len - 1; i >= 0; i--)
        {
            lengthBytes.push_back(static_cast<unsigned char>((length >> (8 * i)) & 0xFF));
        }
        return lengthBytes;
    }
}
vector<unsigned char> buildHeader(const size_t plain_header_len, const vector<unsigned char> &dcid, const vector<unsigned char> &scid)
{   
    // unsigned char packet_type_bit = 0b1;  // Record Type: Handshake
    // unsigned char fix_bit = 0b1;
    // unsigned char long_packet_type = 0b00;
    // unsigned char keep_bit = 0b00; // 受头部包含
    // unsigned char packet_number_length_bit = 0b01;  // 受头部保护，真实长度=该值+1
    // 上面几个字段 一起组成field
    vector<unsigned char> field = {0xc1};                                        // c1: 11000001; cf: 11001111; c3:
    vector<unsigned char> version = {0x00, 0x00, 0x00, 0x01};                    // QUIC Protocol Version
    vector<unsigned char> destination_cid_length = getLenBytes(dcid.size(), 0); // 变长
    vector<unsigned char> destination_cid = dcid;
    vector<unsigned char> source_cid_length = getLenBytes(scid.size(), 0); // 变长
    vector<unsigned char> source_cid = scid;
    vector<unsigned char> token_length = {0x00};
    vector<unsigned char> token = {};
    vector<unsigned char> packet_number = {0x00, 0x01};

    // 计算length包括packetnumber,payload
    size_t packet_number_payload_len = packet_number.size()+plain_header_len+16; // 长度包括包号的长度，加密后的长度（加密前的长度+认证标签16）
    vector<unsigned char> length = getLenBytes(packet_number_payload_len, 0); // 变长变量，数据包剩余部分（也就是数据包号字段和载荷字段）的字节长度

    // 构建QUIC数据包的字节流
    vector<vector<unsigned char>> byteStreams = {field, version, destination_cid_length, destination_cid, source_cid_length, source_cid, token_length, token, length, packet_number};
    vector<unsigned char> header = concatenateByteStreams(byteStreams);

    return header;
}
vector<unsigned char> keyShareExtension()
{
    vector<unsigned char> type = {0x00, 0x33}; // key_share
    vector<unsigned char> length;              // 下面动态赋值

    vector<unsigned char> key_share = {0x00, 0x1d, 0x00, 0x20, 0x9d, 0x3c, 0x94, 0x0d, 0x89, 0x69, 0x0b, 0x84, 0xd0,
                                       0x8a, 0x60, 0x99, 0x3c, 0x14, 0x4e, 0xca, 0x68, 0x4d, 0x10, 0x81, 0x28,
                                       0x7c, 0x83, 0x4d, 0x53, 0x11, 0xbc, 0xf3, 0x2b, 0xb9, 0xda, 0x1a};

    length = getLenBytes(key_share.size(), 2);

    vector<vector<unsigned char>> helf_key_share_extension_datas = {type, length, key_share};
    vector<unsigned char> helf_key_share_extension_data = concatenateByteStreams(helf_key_share_extension_datas);
    return helf_key_share_extension_data;
}
vector<unsigned char> supportedVersionExtension()
{
    vector<unsigned char> type = {0x00, 0x2b};
    vector<unsigned char> length; // 下面动态赋值 bytes.fromhex('0002')
    vector<unsigned char> supported_version = {0x03, 0x04};
    length = getLenBytes(supported_version.size(), 2);
    vector<vector<unsigned char>> helf_supported_version_extension_datas = {type, length, supported_version};
    vector<unsigned char> helf_supported_version_extension_data = concatenateByteStreams(helf_supported_version_extension_datas);
    return helf_supported_version_extension_data;
}
vector<unsigned char> getServerHello()
{
    vector<unsigned char> type = {0x02};          // serverhello
    vector<unsigned char> length;                 // 下面动态赋值
    vector<unsigned char> version = {0x03, 0x03}; // TLS1.2
    vector<unsigned char> random = {0xee, 0xfc, 0xe7, 0xf7, 0xb3, 0x7b, 0xa1, 0xd1, 0x63, 0x2e, 0x96, 0x67,
                                    0x78, 0x25, 0xdd, 0xf7, 0x39, 0x88, 0xcf, 0xc7, 0x98, 0x25, 0xdf, 0x56,
                                    0x6d, 0xc5, 0x43, 0x0b, 0x9a, 0x04, 0x5a, 0x12};
    vector<unsigned char> session_id_length = {0x00};
    vector<unsigned char> cipher_suite = {0x13, 0x01};
    vector<unsigned char> compression_method = {0x00};
    vector<unsigned char> compression_length = {0x00, 0x2e};

    vector<unsigned char> extension_key_share = keyShareExtension();
    vector<unsigned char> extension_supported_version = supportedVersionExtension();
    vector<vector<unsigned char>> helf_crypto_datas = {version, random, session_id_length, cipher_suite,
                                                       compression_method, compression_length, extension_key_share, extension_supported_version};
    vector<unsigned char> helf_crypto_data = concatenateByteStreams(helf_crypto_datas);

    length = getLenBytes(helf_crypto_data.size(), 3);

    vector<vector<unsigned char>> byteStreams = {type, length, helf_crypto_data};
    vector<unsigned char> server_hello = concatenateByteStreams(byteStreams);
    return server_hello;
}

vector<unsigned char> getCryptoFrame()
{
    vector<unsigned char> frame_type = {0x06}; // 0x06
    vector<unsigned char> offset = {0x00};

    vector<unsigned char> crypto_data = getServerHello(); // 假设有 serverHello() 函数返回加密数据

    vector<unsigned char> length = getLenBytes(crypto_data.size(), 0);

    vector<unsigned char> crypto_frame;
    crypto_frame.insert(crypto_frame.end(), frame_type.begin(), frame_type.end());
    crypto_frame.insert(crypto_frame.end(), offset.begin(), offset.end());
    crypto_frame.insert(crypto_frame.end(), length.begin(), length.end());
    crypto_frame.insert(crypto_frame.end(), crypto_data.begin(), crypto_data.end());

    return crypto_frame;
}
vector<vector<unsigned char>> getIntialPlainQuic(const vector<unsigned char> &dcid, const vector<unsigned char> &scid)
{
    vector<unsigned char> ack_frame = getAckFrame();
    vector<unsigned char> crypto_frame = getCryptoFrame();

    vector<unsigned char> plain_payload;
    plain_payload.insert(plain_payload.end(), ack_frame.begin(), ack_frame.end());
    plain_payload.insert(plain_payload.end(), crypto_frame.begin(), crypto_frame.end());

    vector<unsigned char> header = buildHeader(plain_payload.size(), dcid, scid); // 假设有 buildHeader 函数构建头部信息

    vector<vector<unsigned char>> header_plain_payload;
    header_plain_payload.push_back(header);
    header_plain_payload.push_back(plain_payload);

    return header_plain_payload; // 返回header，plain_payload
}
vector<vector<unsigned char>> getHandshakePlainQuic(const vector<unsigned char> &dcid, const vector<unsigned char> &scid)
{
    // uint8_t header_form = 0b1;  // Record Type: Handshake
    // uint8_t fix_bit = 0b1;
    // uint8_t packet_type = 0b10;  // handshake
    vector<unsigned char> field = {0xee}; // 后面4位随机
    vector<unsigned char> version = {0x00, 0x00, 0x00, 0x01}; // QUIC Protocol Version
    vector<unsigned char> destination_cid_length = getLenBytes(dcid.size(), 0); // 变长
    vector<unsigned char> destination_cid = dcid;
    vector<unsigned char> source_cid_length = getLenBytes(scid.size(), 0); // 变长
    vector<unsigned char> source_cid = scid;
    vector<unsigned char> plain_payload = getAckFrame(); // 内容不重要，客户端可能解密不了，待测试
    vector<unsigned char> length = getLenBytes(plain_payload.size(), 0);
    vector<unsigned char> packet_number = {0x00}; // 首个为0

    vector<unsigned char> header;
    header.insert(header.end(), field.begin(), field.end());
    header.insert(header.end(), version.begin(), version.end());
    header.insert(header.end(), destination_cid_length.begin(), destination_cid_length.end());
    header.insert(header.end(), destination_cid.begin(), destination_cid.end());
    header.insert(header.end(), source_cid_length.begin(), source_cid_length.end());
    header.insert(header.end(), source_cid.begin(), source_cid.end());
    header.insert(header.end(), length.begin(), length.end());
    header.insert(header.end(), packet_number.begin(), packet_number.end());


    vector<vector<unsigned char>> header_plain_payload;
    header_plain_payload.push_back(header);
    header_plain_payload.push_back(plain_payload);

    return header_plain_payload; // 返回header，plain_payload
}

///////////////////////////////////////////////////////////////////////////////
// 获取初始密钥和key,iv，hp
///////////////////////////////////////////////////////////////////////////////
typedef struct
{
    size_t len;
    u_char *data;
} quic_str_t;
typedef struct quic_secret_s
{
    quic_str_t secret;
    quic_str_t key;
    quic_str_t iv;
    quic_str_t hp;
} quic_secret_t;
#define quic_string(str)               \
    {                                  \
        sizeof(str) - 1, (u_char *)str \
    }
static void quic_str_to_hex(const char *message, u_char *data, size_t len)
{
    cout<<message;
    for (unsigned int i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
}
static inline uint8_t quic_draft_version(uint32_t version)
{
    if ((version >> 8) == 0xff0000)
        return (uint8_t)version;

    // Facebook mvfst, based on draft -22.
    if (version == 0xfaceb001)
        return 22;

    // Facebook mvfst, based on draft -27.
    if (version == 0xfaceb002 || version == 0xfaceb00e)
        return 27;

    // GQUIC Q050, T050 and T051: they are not really based on any drafts,
    // but we must return a sensible value
    if (version == 0x51303530 || version == 0x54303530 || version == 0x54303531)
        return 27;

    /*
     * https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-15
     * "Versions that follow the pattern 0x?a?a?a?a are reserved for use in
     * forcing version negotiation to be exercised"
     * It is tricky to return a correct draft version: such number is primarly
     * used to select a proper salt (which depends on the version itself), but
     * we don't have a real version here! Let's hope that we need to handle
     * only latest drafts...
     */
    if ((version & 0x0F0F0F0F) == 0x0a0a0a0a)
        return 29;

    return 0;
}
static inline uint8_t quic_draft_is_max(uint32_t version, uint8_t max_version)
{
    uint8_t draft_version = quic_draft_version(version);
    return draft_version && draft_version <= max_version;
}
void LOG(const std::string &message)
{
    std::cerr << "[LOG] " << message << std::endl;
}
static int hkdf_expand(quic_str_t *out, const EVP_MD *digest, const quic_str_t *prk, const quic_str_t *info)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL)
    {
        LOG("EVP_PKEY_CTX_new_id() failed");
        return -1;
    }

    if (EVP_PKEY_derive_init(pctx) <= 0)
    {
        LOG("EVP_PKEY_derive_init() failed");
        goto failed;
    }

    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0)
    {
        LOG("EVP_PKEY_CTX_hkdf_mode() failed");
        goto failed;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, digest) <= 0)
    {
        LOG("EVP_PKEY_CTX_set_hkdf_md() failed");
        goto failed;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, prk->data, prk->len) <= 0)
    {
        LOG("EVP_PKEY_CTX_set1_hkdf_key() failed");
        goto failed;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info->data, info->len) <= 0)
    {
        LOG("EVP_PKEY_CTX_add1_hkdf_info() failed");
        goto failed;
    }
    if (EVP_PKEY_derive(pctx, out->data, &(out->len)) <= 0)
    {
        LOG("EVP_PKEY_derive() failed");
        goto failed;
    }

    EVP_PKEY_CTX_free(pctx);
    return 0;

failed:

    EVP_PKEY_CTX_free(pctx);
    return -1;
}
static int quic_hkdf_expand(const EVP_MD *digest, quic_str_t *out, const quic_str_t *label, const quic_str_t *prk)
{

    uint8_t info_buf[20];
    info_buf[0] = 0;
    info_buf[1] = out->len;
    info_buf[2] = label->len;

    uint8_t *p = (u_char *)memcpy(&info_buf[3], label->data, label->len) + label->len;
    *p = '\0';

    quic_str_t info;
    info.len = 2 + 1 + label->len + 1;
    info.data = info_buf;
    // printf("%zu",info.len);
    // LOG("info：");
    // quic_str_to_hex("info:",info.data,info.len);

    if (hkdf_expand(out, digest, prk, &info) != 0)
    {
        return -1;
    }

    return 0;
}
static int hkdf_extract(quic_str_t *out, const EVP_MD *digest, const quic_str_t *secret, const quic_str_t *initial_salt)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL)
    {
        LOG("EVP_PKEY_CTX_new_id() failed");
        return -1;
    }

    if (EVP_PKEY_derive_init(pctx) <= 0)
    {
        LOG("EVP_PKEY_derive_init() failed");
        goto failed;
    }

    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0)
    {
        LOG("EVP_PKEY_CTX_hkdf_mode() failed");
        goto failed;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, digest) <= 0)
    {
        LOG("EVP_PKEY_CTX_set_hkdf_md() failed");
        goto failed;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret->data, secret->len) <= 0)
    {
        LOG("EVP_PKEY_CTX_set1_hkdf_key() failed");
        goto failed;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, initial_salt->data, initial_salt->len) <= 0)
    {
        LOG("EVP_PKEY_CTX_set1_hkdf_salt() failed");
        goto failed;
    }

    if (EVP_PKEY_derive(pctx, out->data, &(out->len)) <= 0)
    {
        LOG("EVP_PKEY_derive() failed");
        goto failed;
    }

    EVP_PKEY_CTX_free(pctx);
    return 0;

failed:

    EVP_PKEY_CTX_free(pctx);
    return -1;
}
static int quic_keys_set_initial_secret(quic_secret_t *server_secret, const quic_str_t *dcid, uint32_t version)
{
    unsigned int i;
    const quic_str_t initial_salt_v1 = quic_string(
        "\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a");
    const quic_str_t initial_salt_draft_22 = quic_string(
        "\x7f\xbc\xdb\x0e\x7c\x66\xbb\xe9\x19\x3a\x96\xcd\x21\x51\x9e\xbd\x7a\x02\x64\x4a");
    const quic_str_t initial_salt_draft_23 = quic_string(
        "\xc3\xee\xf7\x12\xc7\x2e\xbb\x5a\x11\xa7\xd2\x43\x2b\xb4\x63\x65\xbe\xf9\xf5\x02");
    const quic_str_t initial_salt_draft_29 = quic_string(
        "\xaf\xbf\xec\x28\x99\x93\xd2\x4c\x9e\x97\x86\xf1\x9c\x61\x11\xe0\x43\x90\xa8\x99");
    const quic_str_t initial_salt_draft_q50 = quic_string(
        "\x50\x45\x74\xEF\xD0\x66\xFE\x2F\x9D\x94\x5C\xFC\xDB\xD3\xA7\xF0\xD3\xB5\x6B\x45");
    const quic_str_t initial_salt_draft_t50 = quic_string(
        "\x7f\xf5\x79\xe5\xac\xd0\x72\x91\x55\x80\x30\x4c\x43\xa2\x36\x7c\x60\x48\x83\x10");
    const quic_str_t initial_salt_draft_t51 = quic_string(
        "\x7a\x4e\xde\xf4\xe7\xcc\xee\x5f\xa4\x50\x6c\x19\x12\x4f\xc8\xcc\xda\x6e\x03\x3d");

    const quic_str_t *initial_salt;
    if (version == 0x51303530)
    {
        initial_salt = &initial_salt_draft_q50;
    }
    else if (version == 0x54303530)
    {
        initial_salt = &initial_salt_draft_t50;
    }
    else if (version == 0x54303531)
    {
        initial_salt = &initial_salt_draft_t51;
    }
    else if (quic_draft_is_max(version, 22))
    {
        initial_salt = &initial_salt_draft_22;
    }
    else if (quic_draft_is_max(version, 28))
    {
        initial_salt = &initial_salt_draft_23;
    }
    else if (quic_draft_is_max(version, 32))
    {
        initial_salt = &initial_salt_draft_29;
    }
    else
    {
        initial_salt = &initial_salt_v1;
    }

    /*
     * RFC 9001, section 5.  Packet Protection
     *
     * Initial packets use AEAD_AES_128_GCM.  The hash function
     * for HKDF when deriving initial secrets and keys is SHA-256.
     */
    const EVP_MD *digest = EVP_sha256();

    uint8_t is[SHA256_DIGEST_LENGTH] = {0};
    quic_str_t initial_secret;
    initial_secret.data = is;
    initial_secret.len = SHA256_DIGEST_LENGTH;

    // Use dcid and initial_salt get initial_secret
    if (hkdf_extract(&initial_secret, digest, dcid, initial_salt) != 0)
    {
        return -1;
    }
    quic_str_to_hex("initial_secret:",initial_secret.data, initial_secret.len);
    struct
    {
        quic_str_t label;
        quic_str_t *key;
        quic_str_t *prk;
    } seq[] = {
        /* labels per RFC 9001, 5.1. Packet Protection Keys */
        {quic_string("tls13 server in"), &server_secret->secret, &initial_secret},
        {quic_string("tls13 quic key"), &server_secret->key, &server_secret->secret},
        {quic_string("tls13 quic iv"), &server_secret->iv, &server_secret->secret},
        {quic_string("tls13 quic hp"), &server_secret->hp, &server_secret->secret}};

    for (i = 0; i < (sizeof(seq) / sizeof(seq[0])); i++)
    {
        if (quic_hkdf_expand(digest, seq[i].key, &seq[i].label, seq[i].prk) != 0)
        {
            return -1;
        }
    }

    return 0;
}

///////////////////////////////////////////////////////////////////////////////
// 对数据包进行加密，主要函数：
///////////////////////////////////////////////////////////////////////////////

vector<int> get_length_variable(const vector<unsigned char> &packet, int offset)
{
    vector<int> result;

    int t = pow(2, packet[offset] >> 6);
    result.push_back(t);
    result.push_back(0);
    vector<unsigned char> subVector(packet.begin() + offset, packet.begin() + t + offset);

    for (unsigned char byte : subVector)
    {
        if (t != 1 && result[1] == 0)
        {
            byte &= 0x3f; // 对最高位两位进行设置为0
        }
        result[1] = (result[1] << 8) | byte;
    }
    return result;
}
void LOG(const string &tips, const vector<unsigned char> &bytes)
{
    cout << tips;
    for (const unsigned char &c : bytes)
    {
        printf("%02X ", c);
    }
    cout << endl;
}

// 生成掩码
vector<unsigned char> generate_mask(const vector<unsigned char> &hp_key, const vector<unsigned char> &sample)
{
    AES_KEY aes_key;
    AES_set_encrypt_key(hp_key.data(), 128, &aes_key);

    vector<unsigned char> encrypted(AES_BLOCK_SIZE);
    memset(encrypted.data(), 0, AES_BLOCK_SIZE);
    AES_ecb_encrypt(sample.data(), encrypted.data(), &aes_key, AES_ENCRYPT);

    vector<unsigned char> mask(encrypted.begin(), encrypted.begin() + 5);
    return mask;
}
// 计算数据包号的偏移
int get_offset(const vector<unsigned char> &plain_header)
{
    if ((plain_header[0] & 0x80) == 0x80)
    {
        // 长包头
        // int len_flag = 1;  //1个byte c3 11000011 前5个字段
        // int len_version = 4;
        // int len_dcid_len = 1;
        int len_dcid = static_cast<int>(plain_header[5]); // 正常应该是5
        // int len_scid_len = 1;
        int len_scid = static_cast<int>(plain_header[len_dcid + 6]);

        // 调用 get_length_variable 函数获取 token 变量的长度和值
        vector<int> token_v = get_length_variable(plain_header, 7 + len_dcid + len_scid);
        int len_token_len = token_v[0]; // 变长变量，00:1，01:2，10:4，11:8
        int len_token = token_v[1];     // 目前可见的都是0

        int payload_offset = 7 + len_dcid + len_scid + len_token_len + len_token;
        int len_payload_len = get_length_variable(plain_header, payload_offset)[0]; // 变长变量
        int pn_offset = 7 + len_dcid + len_scid + len_token_len + len_token + len_payload_len;

        // 打印各个变量的值
        cout << "len_dcid, len_scid, len_token_len, len_token, len_payload_len, len_token_len: "
             << len_dcid << ", " << len_scid << ", " << len_token_len << ", " << len_token << ", " << len_payload_len << ", " << len_token_len << endl;

        return pn_offset;
    }
    else
    {
        // 短包头
        int pn_offset = 1 + get_length_variable(plain_header, 1)[0];
        return pn_offset;
    }
}
vector<unsigned char> apply_header_protection(const vector<unsigned char> &mask, const vector<unsigned char> &packet, int pn_offset, int pn_length)
{
    vector<unsigned char> protected_packet(packet);
    if ((protected_packet[0] & 0x80) == 0x80)
    {
        printf("长包头，掩饰4个比特位");
        // 长包头：掩饰4个比特位
        protected_packet[0] ^= (mask[0] & 0x0F); // 对保留比特位、数据包号长度进行保护
    }
    else
    {
        printf("短包头：掩饰5个比特位");
        // 短包头：掩饰5个比特位
        protected_packet[0] ^= (mask[0] & 0x1F);
    }
    for (int i = 0; i < pn_length; i++)
    {
        protected_packet[pn_offset + i] ^= mask[1 + i]; // 对包号进行保护
        printf("%d\n\n",protected_packet[pn_offset + i]);
    }
    return protected_packet;
}

// 测试用， 十六进制字符串转字节流
vector<unsigned char> hexStringToBytes(const string &hexString)
{
    vector<unsigned char> bytes;

    for (size_t i = 0; i < hexString.length(); i += 2)
    {
        string byteString = hexString.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}

vector<unsigned char> encrypt_aead(const vector<unsigned char> &key, const vector<unsigned char> &nonce, const vector<unsigned char> &plaintext, const vector<unsigned char> &associated_data)
{
    int len;
    vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);

    // 初始化
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    // 选择加密套件
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    // 设置iv长度(这里输入的是nonce的，一样)
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), NULL);
    // 设置key,nonce
    EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), nonce.data());
    // 设置关联数据
    EVP_EncryptUpdate(ctx, NULL, &len, associated_data.data(), associated_data.size());
    // 加密数据
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    // 完成加密
    EVP_EncryptFinal_ex(ctx, ciphertext.data(), &len);
    // 获取认证标签
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ciphertext.data() + plaintext.size());
    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(plaintext.size() + len + 16);
    return ciphertext;
}
void secretInit(quic_secret_t &server_secret){
        server_secret.secret.len = SHA256_DIGEST_LENGTH;
    server_secret.secret.data = (u_char *)calloc(SHA256_DIGEST_LENGTH + 1, sizeof(u_char));

    server_secret.key.len = QUIC_AES_128_KEY_LEN;
    server_secret.key.data = (u_char *)calloc(QUIC_AES_128_KEY_LEN + 1, sizeof(u_char));

    server_secret.hp.len = QUIC_AES_128_KEY_LEN;
    server_secret.hp.data = (u_char *)calloc(QUIC_AES_128_KEY_LEN + 1, sizeof(u_char));

    server_secret.iv.len = QUIC_IV_LEN;
    server_secret.iv.data = (u_char *)calloc(QUIC_IV_LEN + 1, sizeof(u_char));
}

vector<unsigned char> getProtectedPacket(vector<unsigned char> plain_header,vector<unsigned char> plain_payload,quic_secret_t server_secret){
    
    // 从包头中获取包号的偏移量,获取包号变量长度和数值
    int pn_offset = get_offset(plain_header);
    vector<int> packet_number_vector = get_length_variable(plain_header, pn_offset);
    LOG("plainHeader:",plain_header);
    LOG("plainPayload:",plain_payload);
    printf("包号偏移量%d\n",pn_offset);

     // 获得key,iv,hp,nonce,
    vector<unsigned char> key(server_secret.key.len);
    memcpy(key.data(), server_secret.key.data, server_secret.key.len);
    vector<unsigned char> iv(server_secret.iv.len);
    memcpy(iv.data(), server_secret.iv.data, server_secret.iv.len);
    vector<unsigned char> hp(server_secret.hp.len);
    memcpy(hp.data(), server_secret.hp.data, server_secret.hp.len);
    vector<unsigned char> nonce(server_secret.iv.len);
    memcpy(nonce.data(), server_secret.iv.data, server_secret.iv.len); //nonce最初设置和iv一样

    // 生成nonce。  iv,packet_number->nonce
    uint8_t packet_number = 0x01;  // 需要同步修改builtHeader(), 实际8..32,这里默认8位，包号为1,
    nonce[11] = iv[11] ^ packet_number;  //修改后的iv,就是nonce,nonce = 包号填充后与iv异或
    LOG("nonce: ",nonce);
    // 加密payload
    vector<unsigned char> encrptyed_payload = encrypt_aead(key, nonce, plain_payload, plain_header);
    LOG("Encrptyed_payload: ",encrptyed_payload);

    // 获取sample
    vector<unsigned char> packet;
    packet.reserve(plain_header.size() + encrptyed_payload.size());
    packet.insert(packet.end(),plain_header.begin(),plain_header.end());
    packet.insert(packet.end(),encrptyed_payload.begin(),encrptyed_payload.end());
    vector<unsigned char> sample(packet.begin()+pn_offset+4, packet.begin()+pn_offset+20);
    LOG("sample: ",sample);

    // 测试获取mask，用于头部保护
    vector<unsigned char> mask = generate_mask(hp, sample);
    LOG("Mask: ",mask);

    // 进行头部保护
    int pn_length  = packet_number_vector[0]+1;
    printf("pn_length:%d\r\n",pn_length);
    vector<unsigned char> protected_packet = apply_header_protection(mask, packet, pn_offset, pn_length);
    LOG("Protected Packet: ",protected_packet);
    return protected_packet;
}

// 加密数据包+头部保护
int test()
{
    // 测试从包头中获取包号的偏移量
    vector<unsigned char> plain_header = hexStringToBytes("c1000000010008f067a5502a4262b50040750001");
    int pn_offset = get_offset(plain_header);
    printf("包号偏移量%d",pn_offset);
    
    // 测试获取包号变量长度和数值
    vector<int> packet_number_vector = get_length_variable(plain_header, pn_offset);
    cout << "Length: " << packet_number_vector[0] << endl;
    cout << "Value: " << packet_number_vector[1] << endl;

    // 获得key,iv,hp,nonce,
    vector<unsigned char> key = {0xcf,0x3a,0x53,0x31,0x65,0x3c,0x36,0x4c,0x88,0xf0,0xf3,0x79,0xb6,0x06,0x7e,0x37};
    vector<unsigned char> iv = {0x0a,0xc1,0x49,0x3c,0xa1,0x90,0x58,0x53,0xb0,0xbb,0xa0,0x3e};
    vector<unsigned char> hp = {0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76, 0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea, 0xa3, 0x14 };
    vector<unsigned char> plaintext = hexStringToBytes("02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00020304");
    
    uint8_t packet_number = 0x01;  //实际8..32,这里默认8位，包号为0
    iv[11] = iv[11] ^ packet_number;  //修改后的iv,就是nonce,nonce = 包号填充后与iv异或

    // 加密payload
    vector<unsigned char> encrptyed_payload = encrypt_aead(key, iv, plaintext, plain_header);
    LOG("Encrptyed_payload: ",encrptyed_payload);

    // 获取sample
    vector<unsigned char> packet;
    packet.reserve(plain_header.size() + encrptyed_payload.size());
    packet.insert(packet.end(),plain_header.begin(),plain_header.end());
    packet.insert(packet.end(),encrptyed_payload.begin(),encrptyed_payload.end());
    vector<unsigned char> sample(packet.begin()+pn_offset+4, packet.begin()+pn_offset+20);
    
    // 测试获取mask，用于头部保护
    vector<unsigned char> mask = generate_mask(hp, sample);
    LOG("Mask: ",mask);

    // 进行头部保护
    int pn_length  = packet_number_vector[0]+1;
    vector<unsigned char> protected_packet = apply_header_protection(mask, packet, pn_offset, pn_length);
    LOG("Protected Packet: ",protected_packet);

    return 0;
}
int main()
{
    // test(); 测试单个函数用

    ////////////////////////////
    ////////解析客户端，已知信息
    ////////////////////////////

    // 设置client_dcid_vector，vector类型
    vector<unsigned char> client_dcid_vector = hexStringToBytes("8394c8f03e515708"); //需要获取，
    
    quic_str_t client_dcid;// client_dcid,结构体，获取密钥用
    client_dcid.data = client_dcid_vector.data();
    client_dcid.len = client_dcid_vector.size();

    // 设置client_scid_vector，vector类型
    vector<unsigned char> client_scid_vector = hexStringToBytes("5555555555555555"); //需要获取，
    
    quic_str_t client_scid;// 服务端的dcid设置为这个值
    client_scid.data = client_scid_vector.data();
    client_scid.len = client_scid_vector.size();



    ////////////////////////////
    ////////服务端处理
    ////////////////////////////

    // // 服务端设置dcid,scid, vector
    vector<unsigned char> dcid_vector(client_scid.len); //需要获取client_scid，二者一致, = client_scid.data,shi
    memcpy(dcid_vector.data(), client_scid.data, client_scid.len);
    vector<unsigned char> scid_vector = hexStringToBytes("f067a5502a4262b5"); //服务器手动设置

    // //设置版本号 
    uint32_t version = 2345;
    
    // 初始化密钥，client_dcid是结构体， 获得server_secret.key.data ,iv.data, hp.data
    quic_secret_t server_secret;
    secretInit(server_secret);
    quic_keys_set_initial_secret(&server_secret,&client_dcid,version);

    // 打印各个密钥，测试用
    quic_str_to_hex("server_secret secret: ",server_secret.secret.data,server_secret.secret.len);
    quic_str_to_hex("server_secret    key: ",server_secret.key.data,server_secret.key.len);
    quic_str_to_hex("server_secret     iv: ",server_secret.iv.data,server_secret.iv.len);
    quic_str_to_hex("server_secret     hp: ",server_secret.hp.data,server_secret.hp.len);

    // 生成inital的 header,plain_payload，使用的是client_dst_connection_id，server_src_connection_id(scid)
    vector<vector<unsigned char>>  inital_quic = getIntialPlainQuic(dcid_vector, scid_vector);
    printByteStream(inital_quic[0]);
    printByteStream(inital_quic[1]);
    vector<unsigned char> header1 = inital_quic[0];
    vector<unsigned char> plain_payload1 = inital_quic[1];
    
    vector<unsigned char> protected_packet = getProtectedPacket(header1,plain_payload1,server_secret);

    // // 生成handshake的 header,plain
    // vector<vector<unsigned char>>  handshake_quic = getHandshakePlainQuic(dcid_vector, scid_vector);
    // printByteStream(handshake_quic[0]);
    // printByteStream(handshake_quic[1]);
    // vector<unsigned char> header2 = handshake_quic[0];
    // vector<unsigned char> plain_payload2 = handshake_quic[1];



    return 0;
}

