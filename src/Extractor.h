#pragma once

#include <queue>
#include <fstream>
#include <mutex>

#include "Sniffer.h"
#include "Config.h"
#include "ConversationFeatures.h"

namespace FeatureExtractor {

	class Extractor
	{

        Sniffer *sniffer;
        Config *config;
        std::queue<ConversationFeatures*> cfs;
        std::mutex conn_mutex; // protects ConversationFeatures queue
        bool is_running_live;
        bool stop_reading;
        volatile bool temination_requested;
        std::ofstream out_stream;
        const char *name;

        void list_interfaces();
        void invalid_option(const char *opt);
        void invalid_option_value(const char *opt, const char *val);
        void parse_args(int argc, char **argv);

        // Push ConversationFeatures queue in a thread
        void push_connection();
        // Read ConversationFeatures queue in another thread, output to stdout
        void read_connection();

	public:

        Extractor();
        Extractor(int argc, char **argv);
        ~Extractor();

        void start();
        void stop();

        void usage();
        
	};
}
