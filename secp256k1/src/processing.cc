// processing.cc

/*******************************************************************************

    PROCESSING -- Puzzle cycle execution support

*******************************************************************************/
#include "../include/easylogging++.h"
#include "../include/conversion.h"
#include "../include/cryptography.h"
#include "../include/definitions.h"
#include "../include/jsmn.h"
#include <ctype.h>
#include <curl/curl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string>





////////////////////////////////////////////////////////////////////////////////
//  Find file size
////////////////////////////////////////////////////////////////////////////////
long int FindFileSize(const char * fileName)
{
    struct stat st;

    CALL_STATUS(stat(fileName, &st), ERROR_STAT, 0);

    return st.st_size;
}

////////////////////////////////////////////////////////////////////////////////
//  Read config file
//  Understands single-level json strings ( {"a":"b", "c":"d", ...})
////////////////////////////////////////////////////////////////////////////////

int ReadConfig(
    const char * fileName,
    uint8_t * sk,
    char * skstr,
    char * from,
    char * to,
    int * keep
)
{
    FILE * in = fopen(fileName, "r");

    long int len = FindFileSize(fileName); 
    json_t config(len, CONF_LEN);

    fread(config.ptr, sizeof(char), len, in);

    fclose(in);
    
    jsmn_parser parser;
    jsmn_init(&parser);
    VLOG(1) << "config string "<< config.ptr;
    
    int numtoks = jsmn_parse(&parser, config.ptr, strlen(config.ptr), config.toks, CONF_LEN);    

    if(numtoks < 0)
    {
        LOG(ERROR) << numtoks << " jsmn config parsing error";
        return EXIT_FAILURE;
    }
    
    bool readNode = false;
    bool readSeed = false;

    for(int i = 1; i < numtoks; i++)
    {
        if(config.jsoneq(i, "node") == 0)
        {
            from[0] = '\0';
            strncpy(from,
                config.GetTokenStart(i+1),
                config.GetTokenLen(i+1)
            );
            VLOG(1) << "nodeaddr from " << std::string(from);
            strcat(from, "/mining/candidate");
            to[0] = '\0';
            strncpy(to,
                config.GetTokenStart(i+1),
                config.GetTokenLen(i+1)
            );
            VLOG(1) << "nodeaddr to " << std::string(to);
            strcat(to, "/mining/solution");
            VLOG(1) << "from url " << from  << " to url " << to;
            readNode = true;
            ++i;
        }
        else if(config.jsoneq(i,"keepPrehash") == 0)
        {
            if(strncmp(config.GetTokenStart(i+1), "true" , 4 ) == 0)
            {
                *keep = 1;
                VLOG(1) << "Setting keepprehash to 1";
            }
            else
            {
                *keep = 0;
            }
            ++i;

        }
        else if(config.jsoneq(i, "seed") == 0)
        {
            --(config.toks[i+1].start);
            *(config.GetTokenStart(i+1)) = '1';
            GenerateSecKey(
                config.GetTokenStart(i+1), 
                config.GetTokenLen(i+1),
                sk,
                skstr
            );
            readSeed = true;
            ++i;
        }

    }
    
    if(readSeed && readNode)
    {
        return EXIT_SUCCESS;
    }
    else
    {
        LOG(ERROR) << "Node or seed were not specified, bad config";
        return EXIT_FAILURE;
    }

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
    const uint8_t * bound
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

// processing.cc
