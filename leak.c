#include "ore.h"

#include <stdio.h> 


static int hex2byte(char *dst, char *src) {
    while(*src) {
        if(' ' == *src) {
            src++;
            continue;
        }
        sscanf(src, "%02X", dst);
        src += 2;
        dst++;
    }
    return 0;
}

void quicksort(byte ciphers[2259][39], int first, int last, ore_params params)
{
   int i, j, pivot, temp, res1;
   byte aux[39];

   ore_ciphertext ctxt1;
   ore_ciphertext ctxt2;

   init_ore_ciphertext(ctxt1, params);
   init_ore_ciphertext(ctxt2, params);

   if(first < last)
   {
        pivot = first;
        i = first;
        j = last;

        while(i < j)
        {
            memcpy(ctxt1->buf,ciphers[i], 39);
            memcpy(ctxt2->buf, ciphers[pivot], 39);

            ore_compare(&res1, ctxt1, ctxt2);

            while (res1 <= 0 && i < last) {
                i++;
                memcpy(ctxt1->buf,ciphers[i], 39);
                memcpy(ctxt2->buf, ciphers[pivot], 39);

                ore_compare(&res1, ctxt1, ctxt2);
            }

            memcpy(ctxt1->buf,ciphers[j], 39);
            memcpy(ctxt2->buf, ciphers[pivot], 39);

            ore_compare(&res1, ctxt1, ctxt2);


            while(res1 > 0) {
                j--;
                memcpy(ctxt1->buf,ciphers[j], 39);
                memcpy(ctxt2->buf, ciphers[pivot], 39);

                ore_compare(&res1, ctxt1, ctxt2);
        
            }

            if(i < j)
            {
                memcpy(aux, ciphers[i], 39);
                memcpy(ciphers[i], ciphers[j], 39);
                memcpy(ciphers[j], aux, 39);
            }
        }

        memcpy(aux, ciphers[pivot], 39);
        memcpy(ciphers[pivot], ciphers[j], 39);
        memcpy(ciphers[j], aux, 39);
        quicksort(ciphers, first, j - 1, params);
        quicksort(ciphers, j + 1, last, params);

   }
}


int main ()
{
    FILE * f = fopen("uniq_ciphertexts", "r");
    int nbits = 31;
    int out_blk_len = ((rand() % (nbits - 2)) + 2);
    ore_params params;
    int ciphertext_size = 39;
    char aux[80];
    int i = 0;


    byte ciphers[2259][39];

    init_ore_params(params, nbits, out_blk_len);

    while(fgets(aux, 80, f))
    {
        hex2byte(&ciphers[i], aux);
        // for (int j=0; j < ciphertext_size; ++j )
        // {
        //     printf("%02x", ciphers[i][j]);
        // }
        // printf("\n");
        // fflush(stdout);
        i++;
    }

    for(i = 0; i < 2259; i++)
    {
        for (int j=0; j < ciphertext_size; ++j )
        {
            printf("%02x", ciphers[i][j]);
        }
        printf("\n");
        fflush(stdout);
    }

    fclose(f);
}