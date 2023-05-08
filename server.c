
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DNS_PORT 50053

int main(int argc, char **argv) {
    // IPv4 UDP のソケットを作成
    int sv_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sv_sock == -1) {
        fprintf(stderr, "recv socket error\n");
        return -1;
    }

    // 待ち受けるIPとポート番号を設定
    struct sockaddr_in sv_addr;
    sv_addr.sin_family = AF_INET;
    sv_addr.sin_addr.s_addr = INADDR_ANY;
    sv_addr.sin_port = htons(DNS_PORT);

    // バインドする
    if (bind(sv_sock, (struct sockaddr *)&sv_addr, sizeof(sv_addr)) == -1) {
        fprintf(stderr, "bind error\n");
        return -1;
    }
    for (int i = 0; i < 1; i++) {
        // 受信
        char recv_buff[1024];
        struct sockaddr_in cl_addr;
        socklen_t cl_addr_len = sizeof(cl_addr);
        ssize_t recv_size = recvfrom(sv_sock, recv_buff, sizeof(recv_buff) - 1, 0, (struct sockaddr *)&cl_addr, &cl_addr_len);
        if (recv_size == -1) {
            fprintf(stderr, "recvfrom error\n");
            continue;
        }
        recv_buff[recv_size] = '\0';
        printf("[%s:%d] >>> %s\n", inet_ntoa(cl_addr.sin_addr), ntohs(cl_addr.sin_port), recv_buff);

        // オウム返し
        if (sendto(sv_sock, recv_buff, recv_size, 0, (struct sockaddr *)&cl_addr, cl_addr_len) == -1) {
            fprintf(stderr, "sendto error (%d:%s)\n", errno, strerror(errno));
            continue;
        }
        printf("[%s:%d] <<< %s\n", inet_ntoa(cl_addr.sin_addr), ntohs(cl_addr.sin_port), recv_buff);
    }
    close(sv_sock);

    return 0;
}