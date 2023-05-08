
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

// DNSパケットヘッダ
struct dns_header {
    u_int16_t id;  // 識別番号
    u_int16_t flags; // フラグ
    u_int16_t qdcount;  // 問い合わせエントリの数
    u_int16_t ancount;  // 応答エントリの数
    u_int16_t nscount;  // オーソリティの数
    u_int16_t arcount;  // 追加情報の数
};

// 問い合わせエントリ
struct dns_query {
    char *qname;  // 照会名 (可変長,0で終端)
    u_int16_t qtype;
    u_int16_t qclass;
};

// 応答エントリ
struct dns_answer {
    char *name;
    u_int16_t type;
    u_int16_t class;
    u_int32_t ttl;
    u_int16_t rdlength;
    char *rdata;
};

/**
 * @brief データを送信し、その応答を受信する関数。戻り値は受信した応答のサイズ
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

    // 宛先IPとポート番号
    struct sockaddr_in sv_addr;
    sv_addr.sin_family = AF_INET;
    sv_addr.sin_addr.s_addr = inet_addr(addr);
    sv_addr.sin_port = htons(port);

    // Clear
    for (int i = 0; i < 100; i++) recv(cl_socket, NULL, 0, MSG_DONTWAIT);

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
 * @brief 問い合わせエントリを生成する関数
 *
 * @param[in] qname 照会名 (必ず'\0'で終端)
 * @param[in] qtype 問い合わせの種類
 * @param[in] qclass 問い合わせのクラス
 * @param[out] buf 出力用バッファ
 * @param[in] buf_size 出力用バッファのサイズ
 * @return int 生成したデータのサイズ。失敗時は-1
 */
int _dns_gen_query(char *qname, u_int16_t qtype, u_int16_t qclass, char *buf, int buf_size) {
    // 可変長エントリqnameの追加していく
    u_int16_t *label_len = (u_int16_t *)buf;
    *label_len = 0;
    int data_size = 1;
    while (qname[data_size - 1] != '\0') {
        if (data_size >= buf_size) {
            fprintf(stderr, "buf size over\n");
            return -1;
        }
        if (qname[data_size - 1] == '.') {
            label_len = (u_int16_t *)(buf + data_size);
            *label_len = 0;
        } else {
            buf[data_size] = qname[data_size - 1];
            *label_len += 1;
        }
        data_size++;
    }
    buf[data_size++] = 0;  // 終端

    // 固定長エントリqtypeとqclassの追加
    *((u_int16_t *)(buf + data_size)) = htons(qtype);
    data_size += sizeof(qtype);
    *((u_int16_t *)(buf + data_size)) = htons(qclass);
    data_size += sizeof(qclass);

    return data_size;
}

/**
 * @brief 問い合わせエントリを構造体にパースして返す関数
 *
 * @param data パース対象のデータ
 * @param query パース結果の構造体を格納する変数
 * @return int パースしたデータのサイズ。
 */
int dns_parse_query(char *data, struct dns_query *query) {
    int parsed_size = 0;

    query->qname = data;  // 可変長
    parsed_size += strlen(query->qname) + 1;

    query->qclass = *((u_int16_t *)(data + parsed_size));
    parsed_size += sizeof(query->qclass);

    query->qtype = *((u_int16_t *)(data + parsed_size));
    parsed_size += sizeof(query->qtype);

    return parsed_size;
}

/**
 * @brief 応答エントリを構造体にパースする関数
 *
 * @param recv_data 受信データ全体
 * @param data パース対象の応答エントリデータ
 * @param answer パース結果の構造体を格納する変数
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
    for (int i = 0; i < size; i++) {
        if (i != 0) { printf("."); }
        printf("%d", (u_int8_t)data[i]);
    }
    printf("\n");
}

int dns_request(char *name, char *dns_addr, int dns_port) {

    char send_buf[512];
    int send_buf_size = 0;

    // ヘッダの追加
    struct dns_header *header = (struct dns_header *)send_buf;
    send_buf_size += sizeof(*header);
    memset(header, 0, sizeof(*header));
    header->id = htons(0x4649);
    header->flags = 0x0100;
    header->qdcount = htons(1);  // 問い合わせエントリ数

    // 問い合わせデータを生成し追加
    int data_size = _dns_gen_query(name, 1, 1, send_buf + send_buf_size, sizeof(send_buf) - send_buf_size);
    if (data_size == -1) {
        fprintf(stderr, "qname error\n");
        return -1;
    }
    send_buf_size += data_size;

    // printf("send: ");
    // print_hex(send_buf, send_buf_size);

    char recv_buf[BUF_SIZE];
    int recv_size = udp_send(dns_addr, dns_port, send_buf, send_buf_size, recv_buf, sizeof(recv_buf));
    if (recv_size == -1) {
        fprintf(stderr, "send data error\n");
        return -1;
    }

    int parsed_size = 0;

    // ヘッダのパース
    struct dns_header *recv_header = (struct dns_header *)recv_buf;
    int qdcount = ntohs(recv_header->qdcount);
    int ancount = ntohs(recv_header->ancount);
    parsed_size += sizeof(struct dns_header);

    // 問い合わせエントリのパース
    for (int i = 0; i < qdcount; i++) {
        // printf("query #%d:\n", i+1);
        struct dns_query query;
        parsed_size += dns_parse_query(recv_buf + parsed_size, &query);
        // printf("qname: %s\n", query.qname);
        // printf("qtype: %d\n", ntohs(query.qtype));
        // printf("qclass: %d\n", ntohs(query.qclass));
        // printf("\n");
    }

    // 応答エントリのパース
    for (int i = 0; i < ancount; i++) {
        printf("answer #%d:\n", i+1);
        struct dns_answer answer;
        parsed_size += dns_parse_answer(recv_buf, recv_buf + parsed_size, &answer);
        printf("name: %s\n", answer.name);
        printf("type: %d\n", ntohs(answer.type));
        printf("class: %d\n", ntohs(answer.class));
        printf("ttl: %d\n", ntohl(answer.ttl));
        printf("rdlength: %d\n", ntohs(answer.rdlength));
        printf("rdata: https://");
        print_addr(answer.rdata, ntohs(answer.rdlength));
    }

    return 0;
}