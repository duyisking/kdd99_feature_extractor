#pragma once

#include <fstream>

#include "Sniffer.h"
#include "Config.h"

namespace FeatureExtractor {

	class Extractor
	{

        Sniffer *sniffer;
        Config *config;
        bool is_running_live;
        volatile bool temination_requested;
        std::ofstream out_stream;
        const char *name;

        void list_interfaces();
        void invalid_option(const char *opt);
        void invalid_option_value(const char *opt, const char *val);
        void parse_args(int argc, char **argv);

	public:

        Extractor(int argc, char **argv);
        ~Extractor();

        void start();
        void stop();

        void usage();
        
	};
}
