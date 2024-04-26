#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <RRCConnectionRequest.h>
#include <RRCConnectionSetup.h>

const int g_bufferSize = 1024;

int getSocketServer(int port);
int acceptConnection(int socketFDescriptor);
void getRRCConnectionRequest(int connectionFDescriptor); 
void sendRRCConnectionSetup(int connectionFDescriptor);

int main(int argc, const char **argv) 
{
    int socket = getSocketServer(8888);               
    while (true)
    {
        int fileDescriptor = acceptConnection(socket);
        getRRCConnectionRequest(fileDescriptor);
        sendRRCConnectionSetup(fileDescriptor);

        close(fileDescriptor);
    }
    close(socket);                                                                                                                                                                   
    return 0;
}

ssize_t receiveMessage(int socketFDescriptor, uint8_t* buffer, size_t size);
ssize_t sendMessage(int socketFDescriptor, uint8_t* buffer, ssize_t size);

int getSocketServer(int port) 
{
    int socketFDescriptor = socket(AF_INET, SOCK_STREAM, 0);

    if (socketFDescriptor < 0) 
    {
        perror("ERROR::can't create socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    if (bind(socketFDescriptor, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) 
    {
        perror("ERROR::can't bind socket");
        exit(EXIT_FAILURE);
    }

    if (listen(socketFDescriptor, 5) < 0) 
    {
        perror("ERROR::can't listen for connections");
        exit(EXIT_FAILURE);
    }

    return socketFDescriptor;
}

int acceptConnection(int socketFDescriptor) 
{
    int connectionFDescriptor = accept(socketFDescriptor, NULL, NULL);

    if (connectionFDescriptor < 0)
    {
        perror("ERROR::can't accept connection");
        exit(EXIT_FAILURE);
    }
    printf("SERVER->Waiting for connection...\n");

    return connectionFDescriptor;
}

void getRRCConnectionRequest(int connectionFDescriptor) 
{
    uint8_t buffer[g_bufferSize];
    ssize_t size = receiveMessage(connectionFDescriptor, buffer, sizeof(buffer));
    RRCConnectionRequest_t* RRCRequest = NULL;
    asn_dec_rval_t decodeTry = asn_decode(NULL, ATS_DER, &asn_DEF_RRCConnectionRequest, (void**)&RRCRequest, buffer, size);

    if (decodeTry.code != RC_OK)
    {
        fprintf(stderr, "ERROR::can't decode RRC Connection Request\n");
        close(connectionFDescriptor);
        exit(EXIT_FAILURE);
    }
    printf("Success->RRCCOnnectionRequest::Recieved\n");

    ASN_STRUCT_FREE(asn_DEF_RRCConnectionRequest, RRCRequest);
}

void sendRRCConnectionSetup(int connectionFDescriptor)
{
    RRCConnectionSetup_t RRCSetup;
    memset(&RRCSetup, 0, sizeof(RRCConnectionSetup_t));
    RRCSetup.rrc_TransactionIdentifier = 1;
    RRCSetup.criticalExtensions.present = RRCConnectionSetup__criticalExtensions_PR_c1;
    RRCSetup.criticalExtensions.choice.c1.present = RRCConnectionSetup__criticalExtensions__c1_PR_rrcConnectionSetup_r8;
    uint8_t buffer[g_bufferSize];
    asn_enc_rval_t encodeTry = der_encode_to_buffer(
        &asn_DEF_RRCConnectionSetup, 
        &RRCSetup, 
        buffer, 
        sizeof(buffer));

    if (encodeTry.encoded < 0) 
    {
        fprintf(stderr, "ERROR::can't encode RRC Connection Setup\n");
        close(connectionFDescriptor);
        exit(EXIT_FAILURE);
    }
    printf("Success->RRCConnectionSetup::Sent\n");

    sendMessage(connectionFDescriptor, buffer, encodeTry.encoded);

}


ssize_t receiveMessage(int socketFDescriptor, uint8_t* buffer, size_t size)
{
    ssize_t receiveTry = recv(socketFDescriptor, buffer, size, 0);

    if (receiveTry < 0) 
    {
        perror("ERROR::can't receive message");
        exit(EXIT_FAILURE);
    }

    return receiveTry;
}

ssize_t sendMessage(int socketFDescriptor, uint8_t* buffer, ssize_t size) 
{
    ssize_t sendTry = send(socketFDescriptor, buffer, size, 0);

    if (sendTry < 0) 
    {
        perror("ERROR::can't send message");
        exit(EXIT_FAILURE);
    }

    return sendTry;
}

