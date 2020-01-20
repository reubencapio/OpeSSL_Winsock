#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
//#include <stdlib.h>
#include <stdio.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/applink.c>

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
//#pragma comment (lib, "Mswsock.lib")
//#pragma comment (lib, "AdvApi32.lib")


#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "4116"
#define FAIL    -1

#define WIN32_LEAN_AND_MEAN

SOCKET OpenConnection(char* hostname, int port)
{
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo* result = NULL;
    struct addrinfo* ptr = NULL;
    struct addrinfo hints;
    char recvbuf[DEFAULT_BUFLEN];
    int iResult;
    int recvbuflen = DEFAULT_BUFLEN;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    iResult = getaddrinfo("127.0.0.1", "4116", &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }
    ptr = result;
    // Create a SOCKET for connecting to server
    ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
    if (ConnectSocket == INVALID_SOCKET) {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // Connect to server.
    iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        closesocket(ConnectSocket);
        ConnectSocket = INVALID_SOCKET;
    }
    return ConnectSocket;
}


SSL_CTX* InitCTX(void)
{
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    const SSL_METHOD* method = TLSv1_2_client_method();  /* Create new client-method instance */
    SSL_CTX* ctx = SSL_CTX_new(method);   /* Create new context */
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}


void ShowCerts(SSL* ssl)
{
    X509* cert;
    char* line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if (cert != NULL)
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        //free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        //free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}
int main(int count, char* strings[])
{
    char buf[1024];
    char acClientRequest[1024] = { 0 };

    if (count != 3)
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }

    SSL_library_init();
    char* hostname = strings[1];
    char* portnum = strings[2];

    SSL_CTX* ctx = InitCTX();
    int server = OpenConnection(hostname, atoi(portnum));
    SSL* ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */


    if (SSL_connect(ssl) == FAIL)   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {
        char acUsername[16] = { 0 };
        char acPassword[16] = { 0 };
        const char* cpRequestMessage = "<Body>\
                                        <UserName>%s<UserName>\
                                        <Password>%s<Password>\
                                        <\Body>";

        printf("Enter the User Name : ");
        scanf("%s", acUsername);

        printf("\n\nEnter the Password : ");
        scanf("%s", acPassword);

        /* construct reply */
        sprintf_s(acClientRequest, cpRequestMessage, acUsername, acPassword);  
        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
       
        /* get any certs */
        ShowCerts(ssl);   
        /* encrypt & send message */
        SSL_write(ssl, acClientRequest, strlen(acClientRequest));  

        /* get reply & decrypt */
        int bytes = SSL_read(ssl, buf, sizeof(buf)); 

        buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);
        /* release connection state */
        SSL_free(ssl);       
    }

    /* close socket */
    closesocket(server);   
    /* release context */
    SSL_CTX_free(ctx);        
    return 0;
}

