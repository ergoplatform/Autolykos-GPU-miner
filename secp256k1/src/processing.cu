// processing.cu

/*******************************************************************************

    PROCESSING -- puzzle cycle execution support

*******************************************************************************/

#include "../include/conversion.h"
#include "../include/cryptography.h"
#include "../include/definitions.h"
#include "../include/jsmn.h"
#include "../include/request.h"
#include <ctype.h>
#include <cuda.h>
#include <curl/curl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

////////////////////////////////////////////////////////////////////////////////
//  Time stamp
////////////////////////////////////////////////////////////////////////////////
char * TimeStamp(
    timestamp_t * stamp
)
{
    // get real time
    clock_gettime(CLOCK_REALTIME, &(stamp->realtime));
    // convert seconds to human-readable form
    stamp->timeinfo = localtime(&((stamp->realtime).tv_sec));
    // form time stamp
    strftime(stamp->timestamp, 30, "%a %m/%d/%Y %H:%M:%S:", stamp->timeinfo);

    // calculate milliseconds
    long int millisec = (stamp->realtime).tv_nsec / 1e6;
    sprintf(stamp->timestamp + 24, "%03d: ", millisec);

    return stamp->timestamp;
}
 
////////////////////////////////////////////////////////////////////////////////
//  Find file size
////////////////////////////////////////////////////////////////////////////////
long int FindFileSize(
    const char * filename
)
{
    struct stat st;

    CALL_STATUS(stat(filename, &st), ERROR_STAT, 0);

    return st.st_size;
}

////////////////////////////////////////////////////////////////////////////////
//  Read config file
////////////////////////////////////////////////////////////////////////////////
int ReadConfig(
    const char * filename,
    uint8_t * sk,
    char * skstr,
    char * from,
    char * to,
    int * keep,
    timestamp_t * stamp
)
{
    FILE * in = fopen(filename, "r");

    long int len = FindFileSize(filename); 
    char config[len + 1];
    config[len] = '\0'; 

    for (int i = 0; (config[i] = fgetc(in)) != EOF; ++i) {}

    fclose(in);

    jsmntok_t tokens[C_LEN];
    jsmn_parser parser;

    jsmn_init(&parser);
    jsmn_parse(&parser, config, len, tokens, C_LEN);

    for (int i = tokens[KEEP_POS].start; i < tokens[KEEP_POS].end; ++i)
    {
        config[i] = toupper(config[i]);
    }

    --(tokens[SEED_POS].start);
    config[tokens[SEED_POS].start] = '1';
    config[tokens[SEED_POS].end] = '\0';
    config[tokens[NODE_POS].end] = '\0';
    config[tokens[KEEP_POS].end] = '\0';

    if (!strncmp(
        config + tokens[KEEP_POS].start, "TRUE",
        tokens[KEEP_POS].end - tokens[KEEP_POS].start
    ))
    {
        *keep = 1;
    }
    else if (strncmp(
        config + tokens[KEEP_POS].start, "FALSE", 
        tokens[KEEP_POS].end - tokens[KEEP_POS].start
    ))
    {
        fprintf(stderr, "ABORT:  Wrong value \"keepPrehash\"\n");

        fprintf(
            stderr, "%s Miner is now terminated\n"
            "========================================"
            "========================================\n",
            TimeStamp(stamp)
        );

        return EXIT_FAILURE;
    }

    GenerateSecKey(
        config + tokens[SEED_POS].start,
        tokens[SEED_POS].end - tokens[SEED_POS].start,
        sk, skstr
    );

    strcpy(from, config + tokens[NODE_POS].start);
    strcpy(
        from + tokens[NODE_POS].end - tokens[NODE_POS].start,
        "/mining/candidate"
    );

    strcpy(to, config + tokens[NODE_POS].start);
    strcpy(
        to + tokens[NODE_POS].end - tokens[NODE_POS].start, "/mining/solution"
    );

    return EXIT_SUCCESS;
}

/// to do /// Make deprecated, move nonce generation to on-the-fly approach
////////////////////////////////////////////////////////////////////////////////
//  Generate consequtive nonces
////////////////////////////////////////////////////////////////////////////////
__global__ void GenerateConseqNonces(
    uint64_t * arr,
    uint32_t len,
    uint64_t base
)
{
    uint32_t tid = threadIdx.x + blockDim.x * blockIdx.x;

    uint64_t nonce = base + tid;

    INPLACE_REVERSE_ENDIAN(&nonce);

    if (tid < len) arr[tid] = nonce;

    return;
}

////////////////////////////////////////////////////////////////////////////////
//  Print Autolukos puzzle state variables
////////////////////////////////////////////////////////////////////////////////
int PrintPuzzleState(
    const uint8_t * mes,
    const uint8_t * pk,
    const uint8_t * sk,
    const uint8_t * w,
    const uint8_t * x,
    const uint8_t * bound,
    timestamp_t * stamp
)
{
    printf("%s Obtained candidate block:\n", TimeStamp(stamp)); 
    printf(
        "       m = 0x%016lX %016lX %016lX %016lX\n",
        REVERSE_ENDIAN((uint64_t *)mes + 0),
        REVERSE_ENDIAN((uint64_t *)mes + 1),
        REVERSE_ENDIAN((uint64_t *)mes + 2),
        REVERSE_ENDIAN((uint64_t *)mes + 3)
    );

    printf("                              Obtained target:\n"); 
    printf(
        "       b = 0x%016lX %016lX %016lX %016lX\n",
        ((uint64_t *)bound)[3], ((uint64_t *)bound)[2],
        ((uint64_t *)bound)[1], ((uint64_t *)bound)[0]
    );

    printf("                              Generated one-time public key:\n"); 
    printf(
        "    w = 0x%02lX %016lX %016lX %016lX %016lX\n",
        ((uint8_t *)w)[0],
        REVERSE_ENDIAN((uint64_t *)(w + 1) + 0),
        REVERSE_ENDIAN((uint64_t *)(w + 1) + 1),
        REVERSE_ENDIAN((uint64_t *)(w + 1) + 2),
        REVERSE_ENDIAN((uint64_t *)(w + 1) + 3)
    );

    fflush(stdout);

    return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
//  Print Autolukos puzzle solution
////////////////////////////////////////////////////////////////////////////////
int PrintPuzzleSolution(
    const uint8_t * nonce,
    const uint8_t * sol
)
{
    printf("   nonce = 0x%016lX\n", REVERSE_ENDIAN((uint64_t *)nonce));

    printf(
        "       d = 0x%016lX %016lX %016lX %016lX\n",
        ((uint64_t *)sol)[3], ((uint64_t *)sol)[2],
        ((uint64_t *)sol)[1], ((uint64_t *)sol)[0]
    );

    fflush(stdout);

    return EXIT_SUCCESS;
}

// processing.cu
