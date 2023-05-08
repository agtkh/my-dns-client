#ifndef __DNS_H__
#define __DNS_H__

/**
 * @brief DNSサーバに名前解決を要求する
 *
 * @param name 名前解決の対象
 * @param dns_addr DNSサーバのIPアドレス
 * @param dns_port DNSサーバのポート番号
 * @return int 失敗時は-1
 */
int dns_request(char *name, char *dns_addr, int dns_port);

#endif
