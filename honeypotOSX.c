#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>

#define MAX_PORTS 10
#define BUFFER_SIZE 4096
#define LOG_FILE "honeypot.log"

typedef struct {
    int port;
    char *banner;
    char *service_name;
} ServiceConfig;

ServiceConfig services[] = {
    {21, "220 FTP Server ready\r\n", "FTP"},
    {22, "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n", "SSH"},
    {23, "Welcome to Telnet Service\r\nLogin: ", "TELNET"},
    {25, "220 mail.example.com ESMTP Postfix\r\n", "SMTP"},
    {80, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n<html><body><h1>It works!</h1></body></html>", "HTTP"},
    {110, "+OK POP3 server ready\r\n", "POP3"},
    {143, "* OK IMAP4rev1 Service Ready\r\n", "IMAP"},
    {306, "\x4a\x00\x00\x00\x0a" "5.7.33-0ubuntu0.18.04.1" "\x00", "MySQL"},
    {389, "RDP", "RDP"},
    {5432, "PostgreSQL", "PostgreSQL"}
};

volatile sig_atomic_t running = 1;

void sigchld_handler(int sig) {
    (void)sig;
    // Limpa processos filhos zombies
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}

void log_event(const char *format, ...) {
    FILE *log = fopen(LOG_FILE, "a");
    if (!log) {
        perror("Erro ao abrir arquivo de log");
        return;
    }
    
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    fprintf(log, "[%s] ", timestamp);
    
    va_list args;
    va_start(args, format);
    vfprintf(log, format, args);
    va_end(args);
    
    fprintf(log, "\n");
    fclose(log);
}

int create_listener(int port) {
    int sockfd;
    struct sockaddr_in addr;
    int opt = 1;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Erro ao criar socket");
        return -1;
    }
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(sockfd);
        return -1;
    }
    
    // Configuração específica para macOS - evita erro "Address already in use"
    #ifdef SO_REUSEPORT
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEPORT");
    }
    #endif
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Erro ao fazer bind na porta %d: %s\n", port, strerror(errno));
        close(sockfd);
        return -1;
    }
    
    if (listen(sockfd, 10) < 0) {
        perror("Erro no listen");
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

void handle_connection(int client_fd, ServiceConfig *service, struct sockaddr_in *client_addr) {
    char buffer[BUFFER_SIZE];
    char ip[INET_ADDRSTRLEN];
    ssize_t bytes_received;
    
    inet_ntop(AF_INET, &(client_addr->sin_addr), ip, INET_ADDRSTRLEN);
    
    log_event("CONEXÃO: %s - IP: %s - Porta: %d", 
              service->service_name, ip, service->port);
    printf("[+] Conexão recebida em %s (porta %d) de %s\n", 
           service->service_name, service->port, ip);
    
    // Envia o banner
    if (service->banner) {
        send(client_fd, service->banner, strlen(service->banner), 0);
        log_event("BANNER ENVIADO: %s - IP: %s", service->service_name, ip);
    }
    
    // Configura timeout para recv (evita conexões penduradas)
    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    // Recebe dados do cliente
    while ((bytes_received = recv(client_fd, buffer, BUFFER_SIZE - 1, 0)) > 0) {
        buffer[bytes_received] = '\0';
        
        // Remove caracteres não imprimíveis para o log
        for (ssize_t i = 0; i < bytes_received; i++) {
            if (buffer[i] < 32 && buffer[i] != '\n' && buffer[i] != '\r' && buffer[i] != '\t') {
                buffer[i] = '.';
            }
        }
        
        log_event("DADOS RECEBIDOS: %s - IP: %s - Tamanho: %zd bytes - Dados: %s", 
                  service->service_name, ip, bytes_received, buffer);
        printf("[*] Dados recebidos de %s em %s: %zd bytes\n", 
               ip, service->service_name, bytes_received);
        
        // Resposta genérica
        if (service->port == 21) {
            send(client_fd, "530 Login incorrect\r\n", 21, 0);
        } else if (service->port == 23) {
            send(client_fd, "Password: ", 10, 0);
        }
    }
    
    log_event("DESCONEXÃO: %s - IP: %s", service->service_name, ip);
    printf("[-] Conexão encerrada de %s em %s\n", ip, service->service_name);
    
    close(client_fd);
}

int main() {
    int listener_fds[MAX_PORTS];
    int num_services = sizeof(services) / sizeof(ServiceConfig);
    fd_set master_set, read_set;
    int max_fd = 0;
    
    // Configura handlers de sinal
    signal(SIGCHLD, sigchld_handler);
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);
    
    printf("=== Honeypot Multi-Porta (macOS) ===\n");
    printf("Arquivo de log: %s\n", LOG_FILE);
    printf("NOTA: Usando portas altas (>1024) para não precisar de sudo\n\n");
    
    log_event("HONEYPOT INICIADO");
    
    FD_ZERO(&master_set);
    
    // Cria listeners para todas as portas
    for (int i = 0; i < num_services; i++) {
        listener_fds[i] = create_listener(services[i].port);
        if (listener_fds[i] < 0) {
            fprintf(stderr, "Aviso: Não foi possível escutar na porta %d (%s)\n", 
                    services[i].port, services[i].service_name);
            continue;
        }
        
        FD_SET(listener_fds[i], &master_set);
        if (listener_fds[i] > max_fd) {
            max_fd = listener_fds[i];
        }
        
        printf("[+] Escutando na porta %d (%s)\n", 
               services[i].port, services[i].service_name);
        log_event("SERVIÇO INICIADO: %s - Porta: %d", 
                  services[i].service_name, services[i].port);
    }
    
    printf("\nHoneypot ativo. Aguardando conexões...\n");
    printf("Pressione Ctrl+C para encerrar.\n\n");
    
    // Loop principal
    while (running) {
        read_set = master_set;
        
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int activity = select(max_fd + 1, &read_set, NULL, NULL, &tv);
        
        if (activity < 0) {
            if (errno == EINTR) {
                continue; // Interrompido por sinal
            }
            perror("Erro no select");
            break;
        }
        
        if (activity == 0) {
            continue; // Timeout
        }
        
        // Verifica cada listener
        for (int i = 0; i < num_services; i++) {
            if (listener_fds[i] < 0) continue;
            
            if (FD_ISSET(listener_fds[i], &read_set)) {
                struct sockaddr_in client_addr;
                socklen_t addr_len = sizeof(client_addr);
                
                int client_fd = accept(listener_fds[i], 
                                      (struct sockaddr *)&client_addr, 
                                      &addr_len);
                
                if (client_fd < 0) {
                    if (errno != EINTR) {
                        perror("Erro no accept");
                    }
                    continue;
                }
                
                // Cria processo filho para tratar a conexão
                pid_t pid = fork();
                if (pid == 0) {
                    // Processo filho
                    for (int j = 0; j < num_services; j++) {
                        if (listener_fds[j] >= 0) {
                            close(listener_fds[j]);
                        }
                    }
                    handle_connection(client_fd, &services[i], &client_addr);
                    exit(0);
                } else if (pid > 0) {
                    // Processo pai
                    close(client_fd);
                } else {
                    perror("Erro no fork");
                    close(client_fd);
                }
            }
        }
    }
    
    printf("\n[!] Encerrando honeypot...\n");
    
    // Cleanup
    for (int i = 0; i < num_services; i++) {
        if (listener_fds[i] >= 0) {
            close(listener_fds[i]);
        }
    }
    
    log_event("HONEYPOT ENCERRADO");
    printf("[!] Honeypot encerrado com sucesso.\n");
    
    return 0;
}
