#include "ore.h"

#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 
#define PORT 8081

typedef struct
{
    byte* id_ctxt_buf;
    byte* salary_ctxt_buf;
} employee_ciphertext;

int init_socket()
{
    int server_fd, new_socket;
    struct sockaddr_in address; 
    int opt = 1; 
    int addrlen = sizeof(address);

    // Creating socket file descriptor 
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
    { 
        perror("socket failed"); 
        exit(EXIT_FAILURE); 
    } 

    // Forcefully attaching socket to the port 8080 
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
                                                  &opt, sizeof(opt))) 
    { 
        perror("setsockopt"); 
        exit(EXIT_FAILURE); 
    } 
    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons( PORT ); 

    // Forcefully attaching socket to the port 8080 
    if (bind(server_fd, (struct sockaddr *)&address,  
                                 sizeof(address))<0) 
    { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    }

    if (listen(server_fd, 3) < 0) 
    { 
        perror("listen"); 
        exit(EXIT_FAILURE); 
    }

    if ((new_socket = accept(server_fd, (struct sockaddr *)&address,  
                       (socklen_t*)&addrlen))<0) 
    { 
        perror("accept"); 
        exit(EXIT_FAILURE); 
    }

    return new_socket;
}

int setup(employee_ciphertext* employee_ciphertexts)
{
    int size, valread, new_socket, employees_count, i;

    new_socket = init_socket();

    valread = read( new_socket , &employees_count, sizeof(employees_count));
    printf("Employees count received...\n");
    #ifdef DEBUG
        printf("Bytes read: %d\n", valread);
        printf("Employees count: %d\n", employees_count);
    #endif
    if (valread != sizeof(employees_count))
    {
        printf("Read only %d from %lu\n", valread, sizeof(employees_count));
        return -1;
    }

    valread = read( new_socket , &size, sizeof(size));
    printf("Ciphertext size received...\n");
    #ifdef DEBUG
        printf("Bytes read: %d\n", valread);
        printf("Ciphertext size: %d \n", size);
    #endif
    if (valread != sizeof(size))
    {
        printf("Read only %d from %lu\n", valread, sizeof(size));
        return -1;
    }

    employee_ciphertexts = calloc(sizeof(employee_ciphertext), employees_count);
    
    printf("Start receiving employee ciphertexts...\n");
    for(i = 0; i < employees_count; i++)
    {
        employee_ciphertexts[i].id_ctxt_buf = calloc(sizeof(byte), size);
        employee_ciphertexts[i].salary_ctxt_buf = calloc(sizeof(byte), size);
        valread = read( new_socket , employee_ciphertexts[i].id_ctxt_buf, size);
        #ifdef DEBUG
            printf("Bytes read: %d\n", valread);
            printf("ID ciphertext: ");
            for (int j=0; j < size; ++j )
            {
                printf("%02x", employee_ciphertexts[i].id_ctxt_buf[j]);
            }
            printf("\n");
        #endif
        if (valread != size)
        {
            printf("Read only %d from %d\n", valread, size);
            return -1;
        }
        valread = read( new_socket , employee_ciphertexts[i].salary_ctxt_buf, size);
        #ifdef DEBUG
            printf("Bytes read: %d\n", valread);
            printf("Salary ciphertext: ");
            for (int j=0; j < size; ++j )
            {
                printf("%02x", employee_ciphertexts[i].salary_ctxt_buf[j]);
            }
            printf("\n");
        #endif
        if (valread != size)
        {
            printf("Read only %d from %d\n", valread, size);
            return -1;
        }
    }
    printf("Employee ciphertexts received...\n");

    shutdown(new_socket, 2);

    return ERROR_NONE;
}

void free_employee_ciphetexts(employee_ciphertext* employee_ciphertexts)
{
    int employees_count = sizeof(employee_ciphertexts)/sizeof(employee_ciphertexts[0]);
    for(int i = 0; i < employees_count; i++)
    {
        free(employee_ciphertexts[i].id_ctxt_buf);
        free(employee_ciphertexts[i].salary_ctxt_buf);
    }
    free(employee_ciphertexts);
}

int main()
{
    employee_ciphertext* employee_ciphertexts = NULL;
    printf("Running server setup...\n");
    setup(employee_ciphertexts);
    printf("Server setup finished...\n");
    free_employee_ciphetexts(employee_ciphertexts);
    return 0;
}