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

int ciphertext_size;
ore_params params;

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
    int valread, new_socket, employees_count, i;

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

    valread = read( new_socket , &ciphertext_size, sizeof(ciphertext_size));
    printf("Ciphertext size received...\n");
    #ifdef DEBUG
        printf("Bytes read: %d\n", valread);
        printf("Ciphertext size: %d \n", ciphertext_size);
    #endif
    if (valread != sizeof(ciphertext_size))
    {
        printf("Read only %d from %lu\n", valread, sizeof(ciphertext_size));
        return -1;
    }

    employee_ciphertexts = calloc(sizeof(employee_ciphertext), employees_count);
    
    printf("Start receiving employee ciphertexts...\n");
    for(i = 0; i < employees_count; i++)
    {
        employee_ciphertexts[i].id_ctxt_buf = calloc(sizeof(byte), ciphertext_size);
        employee_ciphertexts[i].salary_ctxt_buf = calloc(sizeof(byte), ciphertext_size);
        valread = read( new_socket , employee_ciphertexts[i].id_ctxt_buf, ciphertext_size);
        #ifdef DEBUG
            printf("Bytes read: %d\n", valread);
            printf("ID ciphertext: ");
            for (int j=0; j < ciphertext_size; ++j )
            {
                printf("%02x", employee_ciphertexts[i].id_ctxt_buf[j]);
            }
            printf("\n");
        #endif
        if (valread != ciphertext_size)
        {
            printf("Read only %d from %d\n", valread, ciphertext_size);
            return -1;
        }
        valread = read( new_socket , employee_ciphertexts[i].salary_ctxt_buf, ciphertext_size);
        #ifdef DEBUG
            printf("Bytes read: %d\n", valread);
            printf("Salary ciphertext: ");
            for (int j=0; j < ciphertext_size; ++j )
            {
                printf("%02x", employee_ciphertexts[i].salary_ctxt_buf[j]);
            }
            printf("\n");
        #endif
        if (valread != ciphertext_size)
        {
            printf("Read only %d from %d\n", valread, ciphertext_size);
            return -1;
        }
    }
    printf("Employee ciphertexts received...\n");

    shutdown(new_socket, 2);

    return ERROR_NONE;
}

int binary_search_salary(employee_ciphertext* employee_ciphertexts, byte* salary_buf)
{
    int employees_count = sizeof(employee_ciphertexts)/sizeof(employee_ciphertexts[0]);
    int mid_index, res1, res2;
    ore_ciphertext ctxt1;
    ore_ciphertext ctxt2;
    ore_ciphertext ctxt3;

    init_ore_ciphertext(ctxt1, params);
    init_ore_ciphertext(ctxt2, params);
    init_ore_ciphertext(ctxt3, params);

    ctxt1->buf = salary_buf;

    mid_index = employees_count / 2;
    do 
    {
        if (mid_index + 1 == employees_count)
            return mid_index;

        ctxt2->buf = employee_ciphertexts[mid_index].salary_ctxt_buf;
        ctxt3->buf = employee_ciphertexts[mid_index + 1].salary_ctxt_buf;
        ore_compare(&res1, ctxt1, ctxt2);
        ore_compare(&res2, ctxt1, ctxt3);
        
        if (mid_index == 0 && res1 == 1)
            return -1;
        
    }
    while(res1 != -1 && res2 != 1);

    return mid_index;
}

int range(employee_ciphertext* employee_ciphertexts)
{
    int new_socket, valread, min_position, max_position, response_count;
    byte* range_min_buf;
    byte* range_max_buf;

    new_socket = init_socket();

    range_min_buf = calloc(sizeof(byte), ciphertext_size);
    range_max_buf = calloc(sizeof(byte), ciphertext_size);

    valread = read( new_socket , range_min_buf, ciphertext_size);
    #ifdef DEBUG
        printf("Bytes read: %d\n", valread);
        printf("Range min ciphertext: ");
        for (int j=0; j < ciphertext_size; ++j )
        {
            printf("%02x", range_min_buf[j]);
        }
        printf("\n");
    #endif
    if (valread != ciphertext_size)
    {
        printf("Read only %d from %d\n", valread, ciphertext_size);
        return -1;
    }

    valread = read( new_socket , range_max_buf, ciphertext_size);
    #ifdef DEBUG
        printf("Bytes read: %d\n", valread);
        printf("Range max ciphertext: ");
        for (int j=0; j < ciphertext_size; ++j )
        {
            printf("%02x", range_max_buf[j]);
        }
        printf("\n");
    #endif
    if (valread != ciphertext_size)
    {
        printf("Read only %d from %d\n", valread, ciphertext_size);
        return -1;
    }

    min_position = binary_search_salary(employee_ciphertexts, range_min_buf);
    max_position = binary_search_salary(employee_ciphertexts, range_min_buf);

    response_count = max_position - min_position;

    send(new_socket , &response_count, sizeof(response_count), 0);

    for(int i = min_position + 1; i < max_position; i++)
    {
        send(new_socket , employee_ciphertexts[i].id_ctxt_buf, ciphertext_size, 0);
        send(new_socket , employee_ciphertexts[i].salary_ctxt_buf, ciphertext_size, 0);
    }

    free(range_min_buf);
    free(range_max_buf);

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

    int nbits = 31;
    int out_blk_len = ((rand() % (nbits - 2)) + 2);
    init_ore_params(params, nbits, out_blk_len);

    free_employee_ciphetexts(employee_ciphertexts);
    return 0;
}