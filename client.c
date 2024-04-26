#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <RRCConnectionRequest.h>
#include <RRCConnectionSetup.h>

#include "conversions.h"

const int g_bufferSize = 1024;

int getClientSocket(const char *ip, int serverPort);
void sendClientRRCConnectionRequest(int socketFDescriptor);
void getClientRRCConnectionSetup(int socketFDescriptor); 

int main() 
{
    const char* ip = "127.0.0.1";
    int port = 8888;

    int socket = getClientSocket(ip, port);
    sendClientRRCConnectionRequest(socket);
    getClientRRCConnectionSetup(socket);

    close(socket);

    return 0;                                                                                                                                                                                 
}

ssize_t sendMessage(int socketFDescriptor, uint8_t* buffer, ssize_t size);
ssize_t receiveMessage(int socketFDescriptor, uint8_t* buffer, size_t size);

int getClientSocket(const char* ip, int serverPort) 
{
    int socketFDescriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFDescriptor < 0)
    {
        fprintf(stderr, "ERROR::socket creation failed\n");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(serverPort);

    if (inet_pton(AF_INET, ip, &serverAddress.sin_addr) <= 0) 
    {
        fprintf(stderr, "ERROR::bad address\n");
        exit(EXIT_FAILURE);
    }

    if (connect(socketFDescriptor, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) 
    {
        fprintf(stderr, "ERROR::can't connect\n");
        exit(EXIT_FAILURE);
    }

    return socketFDescriptor;
}

void sendClientRRCConnectionRequest(int socketFDescriptor) 
{
    RRCConnectionRequest_t RRCRequest;
    memset(&RRCRequest, 0, sizeof(RRCConnectionRequest_t));

    RRCRequest.criticalExtensions.present = RRCConnectionRequest__criticalExtensions_PR_rrcConnectionRequest_r8;
    RRCRequest.criticalExtensions.choice.rrcConnectionRequest_r8.ue_Identity.present = InitialUE_Identity_PR_randomValue;

    uint8_t buffer[g_bufferSize];
    asn_enc_rval_t encodeTry = der_encode_to_buffer(&asn_DEF_RRCConnectionRequest, &RRCRequest, buffer, sizeof(buffer));
    if (encodeTry.encoded == -1) 
    {
        fprintf(stderr, "ERROR::can't encode\n");
        exit(EXIT_FAILURE);
    }
    printf("Success->RRCConnectionRequest::Sent\n");

    sendMessage(socketFDescriptor, buffer, encodeTry.encoded);
}

void getClientRRCConnectionSetup(int socketFDescriptor) 
{
    uint8_t buffer[g_bufferSize];
    ssize_t size = receiveMessage(socketFDescriptor, buffer, sizeof(buffer));
    RRCConnectionSetup_t* RRCSetup = NULL;
    asn_dec_rval_t decodeTry = asn_decode(
        NULL, 
        ATS_DER,
        &asn_DEF_RRCConnectionSetup, 
        (void**)&RRCSetup, 
        buffer, size);

    if (decodeTry.code != RC_OK) 
    {
        fprintf(stderr, "ERROR::On_the_decode_side\n");
        close(socketFDescriptor);
        exit(EXIT_FAILURE);
    }
    printf("Success->RRCConnectionSetup::Recieved\n");
}

ssize_t sendMessage(int socketFDescriptor, uint8_t* buffer, ssize_t size) 
{
    ssize_t sendTry = send(socketFDescriptor, buffer, size, 0);

    if (sendTry < 0) 
    {
        fprintf(stderr, "ERROR::can't send message\n");
        exit(EXIT_FAILURE);
    }

    return sendTry;
}

ssize_t receiveMessage(int socketFDescriptor, uint8_t* buffer, size_t size) 
{
    ssize_t deceiveTry = recv(socketFDescriptor, buffer, size, 0);

    if (size < 0) 
    {
        exit(EXIT_FAILURE);
    }

    return deceiveTry;
}
