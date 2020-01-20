#undef UNICODE

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "4116"
#define FAIL -1
/////////////////////////

//from microsoft
int create_socket_bind_listen(char* port)
{
    WSADATA wsaData;
    int iResult;

    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    struct addrinfo* result = NULL;
    struct addrinfo hints;

    int iSendResult;
    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, port, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Create a SOCKET for connecting to server
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Setup the TCP listening socket
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        printf("listen failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    return ListenSocket;
}

//non official
void ShowCerts(SSL* ssl)
{
    char* line = 0;
    X509* cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if (cert != NULL)
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}

//non official
void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{
    char buf[1024] = { 0 };
    const char* ServerResponse = "<\Body>\
                                  <Name>aticleworld.com</Name>\
                                  <year>1.5</year>\
                                  <BlogType>Embedede and c\c++<\BlogType>\
                                  <Author>amlendra<Author>\
                                  <\Body>";

    const char* cpValidMessage = "<Body>\
                                        <UserName>aticle<UserName>\
                                        <Password>123<Password>\
                                        <\Body>";

    if (SSL_accept(ssl) == FAIL)     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        ShowCerts(ssl);              /* get any certificates */
        int bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        buf[bytes] = '\0';
        printf("Client msg: \"%s\"\n", buf);
        if (bytes > 0)
        {
            if (strcmp(cpValidMessage, buf) == 0)
            {
                SSL_write(ssl, ServerResponse, (int)strlen(ServerResponse)); /* send reply */
            }
            else
            {
                SSL_write(ssl, "Invalid Message", (int)strlen("Invalid Message")); /* send reply */
            }
        }
        else
        {
            ERR_print_errors_fp(stderr);
        }
    }
    /* get socket connection */
    int sd = SSL_get_fd(ssl);  
    /* release SSL state */
    SSL_free(ssl);     
    /* close connection */
    closesocket(sd);         
}

//official equiv to non official InitServerCTX(void)
void init_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

//official
void cleanup_openssl()
{
    EVP_cleanup();
}

//official
SSL_CTX* create_context()
{
    const SSL_METHOD* method = SSLv23_server_method();

    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

//non official
//create_context() equiv
SSL_CTX* InitServerCTX(void)
{
    /* load & register all cryptos, etc. */
    OpenSSL_add_all_algorithms();
    /* load all error messages */
    SSL_load_error_strings();
    /* create new server-method instance */
    const SSL_METHOD* method = TLSv1_2_server_method();
    /* create new context from method */
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}


//non official
//configure_context() equivalent
void LoadCertificates(SSL_CTX* ctx, 
                      const char* CertFile = "C:\\Users\\reuben.capio\\Documents\\openssl_cert\\host.cert", 
                      const char* KeyFile = "C:\\Users\\reuben.capio\\Documents\\openssl_cert\\host.key")
{
    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

//official equiv to non official LoadCertificates()
void configure_context(SSL_CTX* ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "C:\\Users\\reuben.capio\\Documents\\openssl_cert\\host.cert", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "C:\\Users\\reuben.capio\\Documents\\openssl_cert\\host.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char** argv)
{
    SSL_CTX* ctx = InitServerCTX();
    LoadCertificates(ctx);

    const char* port = "4116";
    int server = create_socket_bind_listen((char*)port);

    /* Handle connections */
    while (1) {
        struct sockaddr_in addr;
        int len = sizeof(addr);


        int client = accept(server, (struct sockaddr*) & addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }
        printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));


        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
        Servlet(ssl);
        

    }

    closesocket(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
    cleanup_openssl();
}
