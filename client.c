#include "ore.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <unistd.h> 
#include <string.h> 
#define PORT 8081

typedef struct {
    unsigned id;
    unsigned salary;
} employee;

int ciphertext_size;

int employee_compare(const void *s1, const void *s2)
{
    employee *e1 = (employee *)s1;
    employee *e2 = (employee *)s2;
    return e1->salary - e2->salary;
}

void sort_employees(employee* employees, int employees_count)
{
    qsort(employees, employees_count, sizeof(employee), employee_compare);
}

int init_socket()
{
    int sock = 0;
    struct sockaddr_in serv_addr;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    { 
        printf("\n Socket creation error \n"); 
        return -1; 
    } 
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(PORT);
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    { 
        printf("\nConnection Failed \n"); 
        return -1; 
    }
    return sock;
}

int setup(ore_secret_key sk, ore_params params, employee* employees, int employees_count)
{
    int i, sock;
    ore_ciphertext id_ctxt, salary_ctxt;

    printf("Generating secret key...\n");
    int err = ore_setup(sk, params);
    printf("Secret key generated...\n");
    
    if (err != ERROR_NONE) {
        return err;
    }

    err = init_ore_ciphertext(id_ctxt, params);
    if (err != ERROR_NONE) {
        return err;
    }
    err = init_ore_ciphertext(salary_ctxt, params);
    if (err != ERROR_NONE) {
        return err;
    }

    printf("Sorting employees...\n");
    sort_employees(employees, employees_count);
    printf("Employees are sorted...\n");

    sock = init_socket();
    if (sock == -1) {
        printf("ERROR Encountered");
        return -1;
    }

    printf("Sending employees count to server...\n");
    send(sock , &employees_count, sizeof(employees_count), 0);
    #ifdef DEBUG
        printf("Employees count: %d\n", employees_count);
    #endif
    printf("Employees count sent...\n");
    ciphertext_size = ore_ciphertext_size(params);
    #ifdef DEBUG
        printf("Ciphertext size: %d \n", ore_ciphertext_size(params));
    #endif
    printf("Sending ciphertext size to server...\n");
    send(sock , &ciphertext_size, sizeof(ciphertext_size), 0);
    printf("Ciphertext size sent...\n");

    printf("Sending ciphertexts...\n");

    for(i = 0; i < employees_count; i++)
    {
        ore_encrypt_ui(id_ctxt, sk, employees[i].id);
        ore_encrypt_ui(salary_ctxt, sk, employees[i].salary);

        #ifdef DEBUG
            printf("ID ciphertext: ");
            for (int j=0; j < ciphertext_size; ++j )
            {
                printf("%02x", id_ctxt->buf[j]);
            }
            printf("\n");
            printf("Salary ciphertext: ");
            for (int j=0; j < ciphertext_size; ++j )
            {
                printf("%02x", salary_ctxt->buf[j]);
            }
            printf("\n");
        #endif
        send(sock , id_ctxt->buf, ciphertext_size, 0);
        send(sock , salary_ctxt->buf, ciphertext_size, 0);
    }

    printf("Ciphertexts sent...\n");

    return ERROR_NONE;
}

int range(ore_secret_key sk, int range_min, int range_max, byte** response, ore_params params)
{
    int i, sock, err, valread, response_count;
    ore_ciphertext range_min_ctxt, range_max_ctxt;

    sock = init_socket();
    if (sock == -1) {
        printf("ERROR Encountered");
        return -1;
    }

    err = init_ore_ciphertext(range_min_ctxt, params);
    if (err != ERROR_NONE) {
        return err;
    }
    err = init_ore_ciphertext(range_max_ctxt, params);
    if (err != ERROR_NONE) {
        return err;
    }

    ore_encrypt_ui(range_min_ctxt, sk, range_min);
    ore_encrypt_ui(range_max_ctxt, sk, range_max);

    send(sock , range_min_ctxt->buf, ciphertext_size, 0);
    send(sock , range_max_ctxt->buf, ciphertext_size, 0);

    valread = read(sock , &response_count, sizeof(response_count));
    printf("Response count received...\n");
    #ifdef DEBUG
        printf("Bytes read: %d\n", valread);
        printf("Response count: %d \n", response_count);
    #endif
    if (valread != sizeof(response_count))
    {
        printf("Read only %d from %lu\n", valread, sizeof(response_count));
        return -1;
    }

    response = calloc(sizeof(byte*), response_count);

    for(i = 0; i < response_count; i++)
    {
        response[i] = calloc(sizeof(byte), ciphertext_size);
        valread = read(sock , response[i], sizeof(response[i]));
        #ifdef DEBUG
            printf("Bytes read: %d\n", valread);
            printf("Response: ");
            for (int j=0; j < ciphertext_size; ++j )
            {
                printf("%02x", response[i][j]);
            }
            printf("\n");
        #endif
        if (valread != sizeof(response[i]))
        {
            printf("Read only %d from %lu\n", valread, sizeof(response[i]));
            return -1;
        }
    }

    return ERROR_NONE;
}

int main()
{
    FILE* fd;
    int i, employees_count = 0;
    employee* employees = NULL;
    int nbits = 31;
    int out_blk_len = ((rand() % (nbits - 2)) + 2);

    fd = fopen ("employees","r");
    if (fd != NULL)
    {
        fscanf(fd, "%d", &employees_count);
        employees = malloc(employees_count * sizeof(employee));
        for(i = 0; i < employees_count; i++)
        {
            fscanf(fd, "%d", &employees[i].salary);
            employees[i].id = i;
        }
        fclose(fd);
    }

    ore_params params;
    init_ore_params(params, nbits, out_blk_len);
    ore_secret_key sk;

    printf("Running client setup...\n");
    setup(sk, params, employees, employees_count);
    printf("Client setup finished...\n");
    return 0;
}