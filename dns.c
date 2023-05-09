
#include "dns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUF_SIZE 512

// DNSレコードタイプ
enum dns_record_type {
    DNS_TYPE_A = 1,      // ホストアドレス
    DNS_TYPE_NS = 2,     // ネームサーバ
    DNS_TYPE_CNAME = 5,  // エイリアス
    DNS_TYPE_SOA = 6,    // スタートオブオーソリティ
    DNS_TYPE_PTR = 12,   // ポインタ
    DNS_TYPE_MX = 15,    // メールエクスチェンジャ
    DNS_TYPE_TXT = 16,   // テキスト
    DNS_TYPE_AAAA = 28,  // IPv6ホストアドレス
    DNS_TYPE_SRV = 33,   // サービス
    DNS_TYPE_ANY = 255   // 任意の型
};

// DNSパケットヘッダ
struct dns_header {
    u_int16_t id;       // 識別番号
    u_int16_t flags;    // フラグ
    u_int16_t qdcount;  // Queryエントリの数
    u_int16_t ancount;  // Answerエントリの数
    u_int16_t nscount;  // オーソリティの数
    u_int16_t arcount;  // 追加情報の数
};

// DNSレコードタイプを文字列に変換する関数
char *dns_type_to_str(u_int16_t type, char *output, int output_size) {
    switch (type) {
        case DNS_TYPE_A:
            strncpy(output, "A", output_size);
            break;
        case DNS_TYPE_NS:
            strncpy(output, "NS", output_size);
            break;
        case DNS_TYPE_CNAME:
            strncpy(output, "CNAME", output_size);
            break;
        case DNS_TYPE_SOA:
            strncpy(output, "SOA", output_size);
            break;
        case DNS_TYPE_PTR:
            strncpy(output, "PTR", output_size);
            break;
        case DNS_TYPE_MX:
            strncpy(output, "MX", output_size);
            break;
        case DNS_TYPE_TXT:
            strncpy(output, "TXT", output_size);
            break;
        case DNS_TYPE_AAAA:
            strncpy(output, "AAAA", output_size);
            break;
        case DNS_TYPE_SRV:
            strncpy(output, "SRV", output_size);
            break;
        case DNS_TYPE_ANY:
            strncpy(output, "ANY", output_size);
            break;
        default:
            strncpy(output, "UNKNOWN", output_size);
            break;
    }
    return output;
}

// Queryエントリ
struct dns_query {
    char *qname;  // 照会名 (可変長,0で終端)
    u_int16_t qtype;
    u_int16_t qclass;
};

// Answerエントリ
struct dns_answer {
    char *name;
    u_int16_t type;
    u_int16_t class;
    u_int32_t ttl;
    u_int16_t rdlength;
    char *rdata;
};

/**
 * @brief データをUDPで送信し、その応答を受信する関数。戻り値は受信した応答のサイズ
 *
 * @param[in] addr 送信先アドレス
 * @param[in] port 送信先ポート番号
 * @param[in] data 送信するデータ
 * @param[in] data_size 送信するデータのサイズ
 * @param[out] recv_buf 応答を受信するバッファ
 * @param[in] recv_buf_size 応答を受信するバッファのサイズ
 * @return int 受信した応答のサイズ。失敗時は-1
 */
int udp_send(char *addr, int port, void *data, int data_size, void *recv_buf, int recv_buf_size) {
    int cl_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (cl_socket == -1) {
        fprintf(stderr, "send socket error (%d:%s)\n", errno, strerror(errno));
        return -1;
    }

    // タイムアウトを設定(3sec, 0msec)
    struct timeval tv = {3, 0};
    setsockopt(cl_socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

    // 宛先IPとポート番号
    struct sockaddr_in sv_addr;
    sv_addr.sin_family = AF_INET;
    sv_addr.sin_addr.s_addr = inet_addr(addr);
    sv_addr.sin_port = htons(port);

    // Clear
    for (int i = 0; i < 8; i++) recv(cl_socket, NULL, 0, MSG_DONTWAIT);

    // パケットをUDPで送信
    if (sendto(cl_socket, data, data_size, 0, (struct sockaddr *)&sv_addr, sizeof(sv_addr)) == -1) {
        fprintf(stderr, "sendto error (%d:%s)\n", errno, strerror(errno));
        close(cl_socket);
        return -1;
    }

    // 応答の受信
    int recv_size = recv(cl_socket, recv_buf, recv_buf_size, 0);
    if (recv_size == -1) {
        fprintf(stderr, "recv error (%d:%s)\n", errno, strerror(errno));
        close(cl_socket);
        return -1;
    }

    close(cl_socket);
    return recv_size;
}

/**
 * @brief 名前をqnameエントリ用の形式に変換する関数
 *
 * @param name 変換する名前
 * @param output 出力先
 * @param output_size 出力先の最大サイズ
 * @return int
 */
int dns_encode_name(char *name, char *output, int output_size) {
    u_int16_t *label_len_ptr = (u_int16_t *)output;
    *label_len_ptr = 0;
    int output_index = 1;
    int name_len = strlen(name);
    for (int i = 0; i < name_len; i++) {
        if (output_index >= output_size - 1) {
            fprintf(stderr, "output size over\n");
            return -1;
        }
        if (name[i] == '.') {
            label_len_ptr = (u_int16_t *)(output + output_index);
            *label_len_ptr = 0;
        } else {
            output[output_index] = name[i];
            *label_len_ptr += 1;
        }
        output_index++;
    }
    output[output_index++] = 0;  // 終端
    return output_index;
}

/**
 * @brief qnameエントリ用の形式を名前に変換する関数
 *
 * @param data qnameエントリ用の形式
 * @param output 変換後の名前
 * @param output_size 変換後の名前の最大サイズ
 * @return int
 */
int dns_decode_name(char *data, char *output, int output_size) {
    int output_index = 0;
    int data_index = 0;
    while (data[data_index] != '\0') {
        int label_len = data[data_index];
        for (int i = 0; i < label_len; i++) {
            output[output_index++] = data[data_index + 1 + i];
        }
        output[output_index++] = '.';
        data_index += (label_len + 1);
    }
    output[output_index++] = 0;
    return output_index;
}

/**
 * @brief Queryエントリを生成する関数
 *
 * @param[in] qname 照会する名前 (必ず'\0'で終端)
 * @param[in] type 照会するDNSレコードタイプ
 * @param[out] buf 出力先バッファ
 * @param[in] buf_size 出力先バッファの最大サイズ
 * @return int 生成したデータのサイズ。失敗時は-1
 */
int dns_gen_query(char *qname, enum dns_record_type type, char *buf, int buf_size) {
    // 可変長qnameエントリの追加
    int data_size = dns_encode_name(qname, buf, buf_size - 4);
    if (data_size == -1) return -1;

    // 固定長エントリqtypeとqclassの追加
    *(u_int16_t *)(buf + data_size) = htons(type);
    *(u_int16_t *)(buf + data_size + 2) = htons(1);  // IN (ほぼ固定でいい)
    data_size += 4;

    return data_size;
}

/**
 * @brief Queryエントリを構造体にパースして返す関数
 *
 * @param[in] data パース対象のデータ
 * @param[out] query パース結果の構造体の保存先
 * @return int パースしたデータのサイズ。
 */
int dns_parse_query(char *data, struct dns_query *query) {
    int parsed_size = 0;

    query->qname = data;  // 可変長
    parsed_size += strlen(data) + 1;

    query->qclass = *(u_int16_t *)(data + parsed_size);
    query->qtype = *(u_int16_t *)(data + parsed_size + 2);
    parsed_size += 4;

    return parsed_size;
}

/**
 * @brief Answerエントリを構造体にパースする関数
 *
 * @param[in] recv_data 受信データ全体
 * @param[in] data パース対象のAnswerエントリデータ
 * @param[out] answer パース結果の構造体を格納する変数
 * @return int パースしたデータのサイズ。
 */
int dns_parse_answer(char *recv_data, char *data, struct dns_answer *answer) {
    int parsed_size = 0;
    if ((*data & 0xc0) == 0xc0) {
        // オフセット形式
        int offset = ntohs(*(u_int16_t *)data) & 0x3FFF;
        answer->name = recv_data + offset;
        parsed_size += 2;
    } else {
        answer->name = data;  // 可変長
        parsed_size += strlen(answer->name) + 1;
    }

    memcpy(&answer->type, data + parsed_size, 10);
    parsed_size += 10;

    int rdlength = ntohs(answer->rdlength);
    answer->rdata = data + parsed_size;  // 可変長
    parsed_size += rdlength;

    return parsed_size;
}

/**
 * @brief バッファの内容を16進数で表示する関数(デバッグ用)
 *
 * @param data 表示するバッファ
 * @param size 表示するバッファのサイズ
 */
void print_hex(char *data, int size) {
    for (int i = 0; i < size; i++) {
        printf("%02x ", (u_int8_t)data[i]);
    }
    printf("\n");
}

/**
 * @brief アドレスを文字列として表示する関数(デバッグ用)
 *
 * @param data アドレス
 * @param size アドレスのサイズ
 */
void print_addr(char *data, int size) {
    if (size == 4) {
        for (int i = 0; i < 4; i++) {
            if (i != 0) {
                printf(".");
            }
            printf("%d", (u_int8_t)data[i]);
        }
    } else if (size == 16) {
        for (int i = 0; i < 16; i += 2) {
            if (i != 0) {
                printf(":");
            }
            printf("%02x%02x", (u_int8_t)data[i], (u_int8_t)data[i + 1]);
        }
    } else {
        fprintf(stderr, "invalid addr size");
    }
    printf("\n");
}

void print_reply_code_msg(u_int8_t reply_code) {
    switch (reply_code) {
        case 0:
            printf("#0 No error\n");
            break;
        case 1:
            printf("#1 Format error\n");
            break;
        case 2:
            printf("#2 Server failure\n");
            break;
        case 3:
            printf("#3 Name error\n");
            break;
        case 4:
            printf("#4 Not implemented\n");
            break;
        case 5:
            printf("#5 Refused\n");
            break;
        default:
            printf("#%d Unknown error\n", reply_code);
            break;
    }
}
int dns_request(char *name, char *dns_addr, int dns_port) {
    char send_buf[512];
    int send_buf_size = 0;

    // ヘッダの追加
    struct dns_header *header = (struct dns_header *)send_buf;
    send_buf_size += sizeof(*header);
    memset(header, 0, sizeof(*header));
    header->id = htons(0x4649);
    header->flags = htons(0x0100);
    header->qdcount = htons(1);  // Queryエントリ数

    // Queryエントリを生成し追加
    int data_size = dns_gen_query(name, DNS_TYPE_A, send_buf + send_buf_size, sizeof(send_buf) - send_buf_size);
    if (data_size == -1) {
        fprintf(stderr, "qname error\n");
        return -1;
    }
    send_buf_size += data_size;

    // データを送信&受信
    char recv_buf[BUF_SIZE];
    int recv_size = udp_send(dns_addr, dns_port, send_buf, send_buf_size, recv_buf, sizeof(recv_buf));
    if (recv_size == -1) {
        fprintf(stderr, "send data error\n");
        return -1;
    }

    int parsed_size = 0;

    // 受信したデータのヘッダのパース
    struct dns_header *recv_header = (struct dns_header *)recv_buf;
    parsed_size += sizeof(struct dns_header);

    int qdcount = ntohs(recv_header->qdcount);  // Queryエントリ数
    int ancount = ntohs(recv_header->ancount);  // Answerエントリ数
    int reply_code = ntohs(recv_header->flags) & 0x000F;
    if (reply_code != 0) {
        print_reply_code_msg(reply_code);
        return -1;
    }

    // Queryエントリのパース(読み飛ばし)
    for (int i = 0; i < qdcount; i++) {
        struct dns_query query;
        parsed_size += dns_parse_query(recv_buf + parsed_size, &query);
    }

    // Answerエントリのパース
    for (int i = 0; i < ancount; i++) {
        struct dns_answer answer;
        parsed_size += dns_parse_answer(recv_buf, recv_buf + parsed_size, &answer);

        char decoded_name[256];
        dns_decode_name(answer.name, decoded_name, sizeof(decoded_name));

        char type_str[10];
        dns_type_to_str(ntohs(answer.type), type_str, sizeof(type_str));

        // 結果を表示
        printf("\n-- answer #%d --\n", i + 1);
        printf("name: %s\n", decoded_name);
        printf("type: %s\n", type_str);
        printf("result: ");
        print_addr(answer.rdata, ntohs(answer.rdlength));
    }

    return 0;
}