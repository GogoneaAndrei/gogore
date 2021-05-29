#include "ore.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <unistd.h> 
#include <string.h> 
#include <unistd.h>
#define PORT 8083

typedef struct {
    unsigned id;
    unsigned salary;
} employee;

int ciphertext_size, sock;
FILE * range_file;

int readn(int sock, void *av, int length)
{
    char *a;
    int m, t;

    a = av;
    t = 0;
    while(t < length){
        m = read(sock, a + t, length - t);
        if(m <= 0){
            if(t == 0)
                return m;
            break;
        }
        t += m;
    }
    return t;
}

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

    printf("Ajung1\n");
    fflush(stdout);
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    { 
        printf("\n Socket creation error \n"); 
        return -1; 
    } 
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr.sin_port = htons(PORT);

    printf("Ajung2\n");
    fflush(stdout);
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    { 
        printf("\nConnection Failed \n"); 
        return -1; 
    }

    printf("Ajung3\n");
    fflush(stdout);
    return sock;
}

int setup(ore_secret_key sk, ore_params params, employee* employees, int employees_count)
{
    int i;
    ore_ciphertext id_ctxt, salary_ctxt;
    FILE * salary_file;

    salary_file = fopen("salaries", "w");

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
            printf("ID: %d; ", employees[i].id);
            printf("ID ciphertext: ");
            for (int j=0; j < ciphertext_size; ++j )
            {
                printf("%02x", id_ctxt->buf[j]);
            }
            printf("\n");
            printf("Salary: %d; ", employees[i].salary);
            fprintf(salary_file, "%d ", employees[i].salary);
            printf("Salary ciphertext: ");
            for (int j=0; j < ciphertext_size; ++j )
            {
                printf("%02x", salary_ctxt->buf[j]);
                fprintf(salary_file, "%02x", salary_ctxt->buf[j]);
            }
            printf("\n");
            fprintf(salary_file, "\n");
        #endif
        send(sock , id_ctxt->buf, ciphertext_size, 0);
        send(sock , salary_ctxt->buf, ciphertext_size, 0);
    }

    printf("Ciphertexts sent...\n");
    fclose(salary_file);
    return ERROR_NONE;
}

int range(ore_secret_key sk, int range_min, int range_max, byte** response, ore_params params)
{
    int i, err, valread, response_count;
    ore_ciphertext range_min_ctxt, range_max_ctxt;

    err = init_ore_ciphertext(range_min_ctxt, params);
    if (err != ERROR_NONE) {
        return err;
    }
    err = init_ore_ciphertext(range_max_ctxt, params);
    if (err != ERROR_NONE) {
        return err;
    }

    printf("Encrypting range_min: %d and range_max: %d\n", range_min, range_max);
    ore_encrypt_ui(range_min_ctxt, sk, range_min);
    ore_encrypt_ui(range_max_ctxt, sk, range_max);
    fflush(stdout);

    #ifdef DEBUG
        fprintf(range_file, "%d %d ", range_min, range_max);
        printf("range_min ciphertext: ");
        for (int j=0; j < ciphertext_size; ++j )
        {
            printf("%02x", range_min_ctxt->buf[j]);
            fprintf(range_file, "%02x", range_min_ctxt->buf[j]);
        }
        printf("\n");
        fprintf(range_file, " ");
        printf("range_max ciphertext: ");
        for (int j=0; j < ciphertext_size; ++j )
        {
            printf("%02x", range_max_ctxt->buf[j]);
            fprintf(range_file, "%02x", range_max_ctxt->buf[j]);
        }
        printf("\n");
        fprintf(range_file, "\n");
    #endif
    
    send(sock , range_min_ctxt->buf, ciphertext_size, 0);
    send(sock , range_max_ctxt->buf, ciphertext_size, 0);

    printf("Sent encrypted results\n");
    fflush(stdout);

    valread = readn(sock , &response_count, sizeof(response_count));
    printf("Response count received...\n");
    #ifdef DEBUG
        printf("Bytes read: %d\n", valread);
        printf("Response count: %d \n", response_count);
        fprintf(range_file, "%d\n", response_count);
    #endif
    if (valread != sizeof(response_count))
    {
        printf("Read only %d from %lu\n", valread, sizeof(response_count));
        return -1;
    }

    response = calloc(sizeof(byte*), response_count);

    for(i = 0; i < response_count; i++)
    {
        printf("Response element %d: \n", i);
        response[i] = calloc(sizeof(byte), ciphertext_size);
        valread = readn(sock , response[i], ciphertext_size);
        #ifdef DEBUG
            printf("Bytes read: %d\n", valread);
            printf("Response: ");
            for (int j=0; j < ciphertext_size; ++j )
            {
                printf("%02x", response[i][j]);
                fprintf(range_file, "%02x", response[i][j]);
            }
            printf("\n");
            fprintf(range_file, "\n");
        #endif
        if (valread != ciphertext_size)
        {
            printf("Read only %d from %lu\n", valread, sizeof(response[i]));
            return -1;
        }

    }

    for(int i = 0; i < response_count; i++)
    {
        free(response[i]);
    }
    free(response);

    return ERROR_NONE;
}

int insert(ore_secret_key sk, ore_params params, employee new_employee)
{
    int err;
    ore_ciphertext id_ctxt, salary_ctxt;

    err = init_ore_ciphertext(id_ctxt, params);
    if (err != ERROR_NONE) {
        return err;
    }
    err = init_ore_ciphertext(salary_ctxt, params);
    if (err != ERROR_NONE) {
        return err;
    }

    ore_encrypt_ui(id_ctxt, sk, new_employee.id);
    ore_encrypt_ui(salary_ctxt, sk, new_employee.salary);

    #ifdef DEBUG
        printf("ID: %d; ", new_employee.id);
        printf("ID ciphertext: ");
        for (int j=0; j < ciphertext_size; ++j )
        {
            printf("%02x", id_ctxt->buf[j]);
        }
        printf("\n");
        printf("Salary: %d; ", new_employee.salary);
        printf("Salary ciphertext: ");
        for (int j=0; j < ciphertext_size; ++j )
        {
            printf("%02x", salary_ctxt->buf[j]);
        }
        printf("\n");
    #endif
    send(sock , id_ctxt->buf, ciphertext_size, 0);
    send(sock , salary_ctxt->buf, ciphertext_size, 0);

    return ERROR_NONE;
}

int delete(ore_secret_key sk, ore_params params, employee employee_to_delete)
{
    int err;
    ore_ciphertext id_ctxt, salary_ctxt;

    err = init_ore_ciphertext(id_ctxt, params);
    if (err != ERROR_NONE) {
        return err;
    }
    err = init_ore_ciphertext(salary_ctxt, params);
    if (err != ERROR_NONE) {
        return err;
    }

    ore_encrypt_ui(id_ctxt, sk, employee_to_delete.id);
    ore_encrypt_ui(salary_ctxt, sk, employee_to_delete.salary);

    #ifdef DEBUG
        printf("ID: %d; ", employee_to_delete.id);
        printf("ID ciphertext: ");
        for (int j=0; j < ciphertext_size; ++j )
        {
            printf("%02x", id_ctxt->buf[j]);
        }
        printf("\n");
        printf("Salary: %d; ", employee_to_delete.salary);
        printf("Salary ciphertext: ");
        for (int j=0; j < ciphertext_size; ++j )
        {
            printf("%02x", salary_ctxt->buf[j]);
        }
        printf("\n");
    #endif
    send(sock , id_ctxt->buf, ciphertext_size, 0);
    send(sock , salary_ctxt->buf, ciphertext_size, 0);

    return ERROR_NONE;
}

void free_employee_ciphetexts(employee* employees)
{
    free(employees);
}


int main()
{
    FILE* fd;
    int i, size, line_len, employees_count = 0, range_min, range_max, range_count = 0;
    employee* employees = NULL, new_employee;
    int nbits = 31;
    byte** range_response = NULL;
    char command[80], token[80];
    int out_blk_len = ((rand() % (nbits - 2)) + 2);
    
    printf("Socket init...\n");
    fflush(stdout);
    sock = init_socket();
    if (sock == -1) {
        printf("ERROR Encountered");
        return -1;
    }

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
        //fclose(fd);
    }

    ore_params params;
    init_ore_params(params, nbits, out_blk_len);
    ore_secret_key sk;

    printf("Running client setup...\n");
    setup(sk, params, employees, employees_count);
    printf("Client setup finished...\n");

    fscanf(fd, "%d", &range_count);
    range_file = fopen("ranges2", "w");
    for(i = 0; i < range_count; i++)
    {
        fscanf(fd, "%d %d", &range_min, &range_max);
        size = 5;
        send(sock, &size, sizeof(size), 0);
        send(sock , "RANGE", size, 0);
        range(sk, range_min, range_max, range_response, params);
    }
    fclose(range_file);
    fclose(fd);

    while (1)
    {
        printf("Enter command: ");

        scanf("%s", command);
        
        if (strcmp(command, "EXIT") == 0)
        {
            size = 4;
            send(sock, &size, sizeof(size), 0);
            send(sock, "EXIT", size, 0);
            break;
        }
        else if (strcmp(command, "RANGE") == 0)
        {
            scanf("%d %d", &range_min, &range_max);
            size = 5;
            send(sock, &size, sizeof(size), 0);
            send(sock , "RANGE", size, 0);
            range(sk, range_min, range_max, range_response, params);
        }
        else if (strcmp(command, "INSERT") == 0)
        {
            scanf("%d %d", &new_employee.id, &new_employee.salary);
            size = 6;
            send(sock, &size, sizeof(size), 0);
            send(sock, "INSERT", size, 0);
            insert(sk, params, new_employee);
        }
        else if (strcmp(command, "DELETE") == 0)
        {
            scanf("%d %d", &new_employee.id, &new_employee.salary);
            size = 6;
            send(sock, &size, sizeof(size), 0);
            send(sock, "DELETE", size, 0);
            delete(sk, params, new_employee);
        }
        else
        {
            printf("Invalid command\n");
        }

        
    }

    printf("Freeing memory...\n");
    free_employee_ciphetexts(employees);


    return 0;
}