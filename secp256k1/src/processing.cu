// processing.cu

/*******************************************************************************

    PROCESSING -- puzzle cycle execution support

*******************************************************************************/

#include "../include/conversion.h"
#include "../include/cryptography.h"
#include "../include/definitions.h"
#include "../include/jsmn.h"
//#include "../include/request.h"
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

/// ////////////////////////////////////////////////////////////////////////////////
/// //  Time stamp
/// ////////////////////////////////////////////////////////////////////////////////
/// char * TimeStamp(
///     timestamp_t * stamp
/// )
/// {
///     // get real time
///     clock_gettime(CLOCK_REALTIME, &(stamp->realtime));
///     // convert seconds to human-readable form
///     stamp->timeinfo = localtime(&((stamp->realtime).tv_sec));
///     // form time stamp
///     strftime(stamp->timestamp, 30, "%a %m/%d/%Y %H:%M:%S:", stamp->timeinfo);
/// 
///     // calculate milliseconds
///     long int millisec = (stamp->realtime).tv_nsec / 1e6;
///     sprintf(stamp->timestamp + 24, "%03d: ", millisec);
/// 
///     return stamp->timestamp;
/// }
 
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
    int * keep//,
    //timestamp_t * stamp
)
{
    FILE * in = fopen(filename, "r");

    long int len = FindFileSize(filename); 
    json_t config(len, CONF_LEN);

    for (int i = 0; (config.ptr[i] = fgetc(in)) != EOF; ++i) {}

    fclose(in);

    jsmn_parser parser;
    jsmn_init(&parser);

    jsmn_parse(&parser, config.ptr, config.len, config.toks, CONF_LEN);

    for (
        int i = config.GetTokenStartPos(KEEP_POS);
        i < config.GetTokenEndPos(KEEP_POS);
        ++i
    )
    {
        config.ptr[i] = toupper(config.ptr[i]);
    }

    --(config.toks[SEED_POS].start);
    *(config.GetTokenStart(SEED_POS)) = '1';
    *(config.GetTokenEnd(SEED_POS)) = '\0';
    *(config.GetTokenEnd(NODE_POS)) = '\0';
    *(config.GetTokenEnd(KEEP_POS)) = '\0';

    if (!strncmp(
        config.GetTokenStart(KEEP_POS), "TRUE", config.GetTokenLen(KEEP_POS)
    ))
    {
        *keep = 1;
    }
    else if (strncmp(
        config.GetTokenStart(KEEP_POS), "FALSE", config.GetTokenLen(KEEP_POS)
    ))
    {
        fprintf(stderr, "ABORT:  Wrong value \"keepPrehash\"\n");

        fprintf(
            stderr, "Miner is now terminated\n"
            "========================================"
            "========================================\n"//,
            //TimeStamp(stamp)
        );

        return EXIT_FAILURE;
    }

    GenerateSecKey(
        config.GetTokenStart(SEED_POS), config.GetTokenLen(SEED_POS), sk, skstr
    );

    strcpy(from, config.GetTokenStart(NODE_POS));
    strcpy(from + config.GetTokenLen(NODE_POS), "/mining/candidate");

    strcpy(to, config.GetTokenStart(NODE_POS));
    strcpy(to + config.GetTokenLen(NODE_POS), "/mining/solution");

    return EXIT_SUCCESS;
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
    const uint8_t * bound//,
    //timestamp_t * stamp
)
{
    printf("Obtained candidate block:\n"); 
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
    printf("   nonce = 0x%016lX\n", *((uint64_t *)nonce));

    printf(
        "       d = 0x%016lX %016lX %016lX %016lX\n",
        ((uint64_t *)sol)[3], ((uint64_t *)sol)[2],
        ((uint64_t *)sol)[1], ((uint64_t *)sol)[0]
    );

    fflush(stdout);

    return EXIT_SUCCESS;
}

// processing.cu
