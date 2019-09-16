#ifndef HTTPAPI_H
#define HTTPAPI_H

#include "httplib.h"
#include <vector>
#include <string>
#include <nvml.h>
#include <unordered_map>
#include <sstream>
#include <chrono>

void HttpApiThread(std::vector<double>* hashrates, std::vector<std::pair<int,int>>* props);


#endif