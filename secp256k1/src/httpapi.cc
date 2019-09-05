#include "../include/httpapi.h"
using namespace httplib;


inline int key(std::pair<int,int> x)
{
    return 100*x.first + x.second;
}


// outputs JSON with GPUs hashrates, temps, and power usages
void HttpApiThread(std::vector<double>* hashrates, std::vector<std::pair<int,int>>* props)
{
    Server svr;

    svr.Get("/", [&](const Request& req, Response& res) {
        
        std::unordered_map<int, double> hrMap;
        for(int i = 0; i < (*hashrates).size() ; i++)
        {
            hrMap[key((*props)[i])] = (*hashrates)[i];
        }
        
        
        
        std::stringstream strBuf;
        strBuf << "{ ";
        
        // NVML data 
        double totalHr = 0;
        nvmlReturn_t result;
        result = nvmlInit();
        if (result == NVML_SUCCESS)
        { 

            unsigned int devcount;
            result = nvmlDeviceGetCount(&devcount);
            bool first = true;
            strBuf << " \"gpus\":" << devcount << " , ";
            strBuf << " \"devices\" : [ " ;

            for(int i = 0; i < devcount; i++)
            {
                std::stringstream deviceInfo;
                nvmlDevice_t device;
                result = nvmlDeviceGetHandleByIndex(i, &device);
                if(result == NVML_SUCCESS)
                {
                    

                    nvmlPciInfo_t pciInfo;
                    result = nvmlDeviceGetPciInfo ( device, &pciInfo );
                    if(result != NVML_SUCCESS) { continue; }

                    if(first)
                    {
                        first = false;
                    }
                    else
                    {
                        deviceInfo << " , ";        
                    }

                    deviceInfo << " \"gpu" << i << "\" : { ";
                    char devname[256];
                    result = nvmlDeviceGetName (device, devname, 256 );
                    deviceInfo << " \"devname\" : \"" << devname << "\" , ";                    
                    deviceInfo << " \"pciid\" : \"" << pciInfo.busId << "\" , ";
                    double hrate;
                    try{

                        hrate = hrMap.at(key(std::make_pair((int)pciInfo.bus, (int)pciInfo.device)));
                        deviceInfo << " \"hashrate\" : " << hrate << " , ";
                        totalHr += hrate;
                    }
                    catch (...) // if GPU is not mining ( CUDA_VISIBLE_DEVICES is set)
                    {}
                    unsigned int temp;
                    unsigned int power;
                    result = nvmlDeviceGetPowerUsage ( device, &power );
                    result = nvmlDeviceGetTemperature ( device, NVML_TEMPERATURE_GPU, &temp );
                    deviceInfo << " \"power\" : " << power/1000 << " , ";
                    deviceInfo << " \"temperature\" : " << temp << " }";
                    strBuf << deviceInfo.str();
                }
            }

            strBuf << " ] , \"total\": " << totalHr  ;


            result = nvmlShutdown();
        }
        else
        {
            strBuf << " \"error\": \"NVML error, possibly some device fell off the bus\"";
        }

        strBuf << " } ";


        std::string str = strBuf.str();
        res.set_content(str.c_str(), "text/plain");
    });
    

    #ifdef HTTPAPI_PORT
    svr.listen("0.0.0.0", HTTPAPI_PORT);
    #else
    svr.listen("0.0.0.0", 32067);
    #endif
}