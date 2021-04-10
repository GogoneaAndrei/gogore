#include "ore.h"

#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 
#define PORT 8083

typedef struct
{
    byte* id_ctxt_buf;
    byte* salary_ctxt_buf;
} employee_ciphertext;

employee_ciphertext* employee_ciphertexts;
int ciphertext_size, new_socket, employees_count;
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

int setup()
{
    int valread, i;

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

    for(i = 0; i < employees_count; i++)
    {
        printf("Salary ciphertext: ");
        fflush(stdout);
            for (int j=0; j < ciphertext_size; ++j )
            {
                printf("%02x", employee_ciphertexts[i].salary_ctxt_buf[j]);
                fflush(stdout);
            }
            printf("\n");
            fflush(stdout);
    }

    return ERROR_NONE;
}

int binary_search_salary(byte* salary_buf)
{
    int min_index, max_index, mid_index, res1, res2;
    ore_ciphertext ctxt1;
    ore_ciphertext ctxt2;
    ore_ciphertext ctxt3;

    init_ore_ciphertext(ctxt1, params);
    init_ore_ciphertext(ctxt2, params);
    init_ore_ciphertext(ctxt3, params);

    memcpy(ctxt1->buf, salary_buf, ciphertext_size);

    min_index = 0;
    max_index = employees_count;
    while(1)
    {   
        mid_index = (max_index + min_index) / 2;
        if (mid_index + 1 == employees_count)
            return mid_index;

        memcpy(ctxt2->buf, employee_ciphertexts[mid_index].salary_ctxt_buf, ciphertext_size);
        memcpy(ctxt3->buf, employee_ciphertexts[mid_index + 1].salary_ctxt_buf, ciphertext_size);

        ore_compare(&res1, ctxt1, ctxt2);
        ore_compare(&res2, ctxt1, ctxt3);
        
        if (mid_index == 0 && res1 == -1)
        {
            return -1;
        }

        if (res1 == 0 && res2 == -1)
        {
            return mid_index;
        }
        
        if (res2 == 0)
        {
            min_index = mid_index;
        }
        
        if (res1 == -1 && res2 == -1)
        {
            max_index = mid_index;
        }
        
        if (res1 == 1 && res2 == 1)
        {
            min_index = mid_index + 1;
        }

        if (res1 == 1 && res2 == -1)
        {
            return mid_index;
        }
        
    }
}

int range()
{
    int valread, min_position, max_position, response_count;
    byte* range_min_buf;
    byte* range_max_buf;

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

    printf("COMPLETE QUERY: RANGE ");
    for (int j=0; j < ciphertext_size; ++j )
    {
        printf("%02x", range_min_buf[j]);
    }
    printf(" ");
    for (int j=0; j < ciphertext_size; ++j )
    {
        printf("%02x", range_max_buf[j]);
    }
    printf("\n");


    min_position = binary_search_salary(range_min_buf);
    max_position = binary_search_salary(range_max_buf);

    response_count = max_position - min_position;

    send(new_socket , &response_count, sizeof(response_count), 0);

    for(int i = min_position + 1; i <= max_position; i++)
    {
        send(new_socket , employee_ciphertexts[i].salary_ctxt_buf, ciphertext_size, 0);
    }

    free(range_min_buf);
    free(range_max_buf);

    return ERROR_NONE;
}

int insert()
{
    int valread, position;
    byte* salary_buf;
    byte* id_buf;

    id_buf = calloc(sizeof(byte), ciphertext_size);
    salary_buf = calloc(sizeof(byte), ciphertext_size);

    valread = read( new_socket , id_buf, ciphertext_size);
    #ifdef DEBUG
        printf("Bytes read: %d\n", valread);
        printf("ID ciphertext: ");
        for (int j=0; j < ciphertext_size; ++j )
        {
            printf("%02x", id_buf[j]);
        }
        printf("\n");
    #endif
    if (valread != ciphertext_size)
    {
        printf("Read only %d from %d\n", valread, ciphertext_size);
        return -1;
    }
    valread = read( new_socket , salary_buf, ciphertext_size);
    #ifdef DEBUG
        printf("Bytes read: %d\n", valread);
        printf("Salary ciphertext: ");
        for (int j=0; j < ciphertext_size; ++j )
        {
            printf("%02x", salary_buf[j]);
        }
        printf("\n");
    #endif
    if (valread != ciphertext_size)
    {
        printf("Read only %d from %d\n", valread, ciphertext_size);
        return -1;
    }

    printf("COMPLETE QUERY: INSERT (");
    for (int j=0; j < ciphertext_size; ++j )
    {
        printf("%02x", id_buf[j]);
    }
    printf(" ");
    for (int j=0; j < ciphertext_size; ++j )
    {
        printf("%02x", salary_buf[j]);
    }
    printf(")\n");

    position = binary_search_salary(salary_buf);

    employee_ciphertexts = realloc(employee_ciphertexts, sizeof(employee_ciphertext) * (employees_count + 1));

    for (int i = employees_count - 1; i > position; i--)
    {
        employee_ciphertexts[i + 1].id_ctxt_buf = employee_ciphertexts[i].id_ctxt_buf;
        employee_ciphertexts[i + 1].salary_ctxt_buf = employee_ciphertexts[i].salary_ctxt_buf;

    }

    employee_ciphertexts[position + 1].id_ctxt_buf = id_buf;
    employee_ciphertexts[position + 1].salary_ctxt_buf = salary_buf;
    employees_count += 1;


     for(int i = 0; i < employees_count; i++)
    {
        printf("Salary ciphertext: ");
        fflush(stdout);
        for (int j=0; j < ciphertext_size; ++j )
        {
            printf("%02x", employee_ciphertexts[i].salary_ctxt_buf[j]);
            fflush(stdout);
        }
        printf("\n");
        fflush(stdout);
    }

    return ERROR_NONE;
}

int delete()
{
    int valread, position;
    byte* salary_buf;
    byte* id_buf;

    id_buf = calloc(sizeof(byte), ciphertext_size);
    salary_buf = calloc(sizeof(byte), ciphertext_size);

    valread = read( new_socket , id_buf, ciphertext_size);
    #ifdef DEBUG
        printf("Bytes read: %d\n", valread);
        printf("ID ciphertext: ");
        for (int j=0; j < ciphertext_size; ++j )
        {
            printf("%02x", id_buf[j]);
        }
        printf("\n");
    #endif
    if (valread != ciphertext_size)
    {
        printf("Read only %d from %d\n", valread, ciphertext_size);
        return -1;
    }
    valread = read( new_socket , salary_buf, ciphertext_size);
    #ifdef DEBUG
        printf("Bytes read: %d\n", valread);
        printf("Salary ciphertext: ");
        for (int j=0; j < ciphertext_size; ++j )
        {
            printf("%02x", salary_buf[j]);
        }
        printf("\n");
    #endif
    if (valread != ciphertext_size)
    {
        printf("Read only %d from %d\n", valread, ciphertext_size);
        return -1;
    }

    printf("COMPLETE QUERY: DELETE (");
    for (int j=0; j < ciphertext_size; ++j )
    {
        printf("%02x", id_buf[j]);
    }
    printf(" ");
    for (int j=0; j < ciphertext_size; ++j )
    {
        printf("%02x", salary_buf[j]);
    }
    printf(")\n");

    position = binary_search_salary(salary_buf);

    printf("%d\n", position);
    fflush(stdout);

    int eq_salary = 0, eq_id = 0;
    int count = 0, distance = 0;

    ore_ciphertext ctxt1;
    ore_ciphertext ctxt2;
    ore_ciphertext ctxt3;
    ore_ciphertext ctxt4;

    init_ore_ciphertext(ctxt1, params);
    init_ore_ciphertext(ctxt2, params);
    init_ore_ciphertext(ctxt3, params);
    init_ore_ciphertext(ctxt4, params);

    while(eq_salary == 0)
    {
        if ((position - distance) < 0)
            break;

        memcpy(ctxt1->buf, salary_buf, ciphertext_size);
        memcpy(ctxt2->buf, employee_ciphertexts[position - distance].salary_ctxt_buf, ciphertext_size);
        memcpy(ctxt3->buf, id_buf, ciphertext_size);
        memcpy(ctxt4->buf, employee_ciphertexts[position - distance].id_ctxt_buf, ciphertext_size);


        ore_compare(&eq_salary, ctxt1, ctxt2);
        ore_compare(&eq_id, ctxt3, ctxt4);

        if (eq_salary == 0 && eq_id == 0)
        {
            for(int i = position - distance + 1; i < employees_count; i++)
            {
                employee_ciphertexts[i - 1].id_ctxt_buf = employee_ciphertexts[i].id_ctxt_buf;
                employee_ciphertexts[i - 1].salary_ctxt_buf = employee_ciphertexts[i].salary_ctxt_buf;
            }
            count++;
        }
        distance++;
    }

    employee_ciphertexts = realloc(employee_ciphertexts, sizeof(employee_ciphertext) * (employees_count - count));
    employees_count -= count;

     for(int i = 0; i < employees_count; i++)
    {
        printf("Salary ciphertext: ");
        fflush(stdout);
        for (int j=0; j < ciphertext_size; ++j )
        {
            printf("%02x", employee_ciphertexts[i].salary_ctxt_buf[j]);
            fflush(stdout);
        }
        printf("\n");
        fflush(stdout);
    }

    return ERROR_NONE;
}


void free_employee_ciphetexts()
{
    for(int i = 0; i < employees_count; i++)
    {
        free(employee_ciphertexts[i].id_ctxt_buf);
        free(employee_ciphertexts[i].salary_ctxt_buf);
    }
    free(employee_ciphertexts);
}

int main()
{
    char command[80];
    int size;

    printf("Socket init...\n");
    fflush(stdout);
    new_socket = init_socket();

    printf("Running server setup...\n");
    setup();
    printf("Server setup finished...\n");

    int nbits = 31;
    int out_blk_len = ((rand() % (nbits - 2)) + 2);
    init_ore_params(params, nbits, out_blk_len);

    while (1)
    {
        memset(command, 0, 80);
        read( new_socket , &size, sizeof(size));
        read( new_socket , command, size);

        printf("Command received: %s\n", command);
        fflush(stdout);
        
        if (strcmp(command, "EXIT") == 0)
        {
            break;
        }
        else if (strcmp(command, "RANGE") == 0)
        {
            range();
        }
        else if (strcmp(command, "INSERT") == 0)
        {
            insert();
        }
        else if (strcmp(command, "DELETE") == 0)
        {
            delete();
        }
        else
        {
            printf("Command not recognized\n");
        }
    }

    printf("Freeing memory...\n");
    shutdown(new_socket, 2);
    
    free_employee_ciphetexts();
    return 0;
}