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

        void list_interfaces();
        void invalid_option(const char *opt, const char *progname);
        void invalid_option_value(const char *opt, const char *val, const char *progname);
	public:
        Extractor(int argc, char **argv);
        ~Extractor();

        void start();
        void stop();

        void usage(const char *name);
        void parse_args(int argc, char **argv);
	};
}
