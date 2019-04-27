#pragma once

#include "Sniffer.h"
#include "Config.h"

namespace FeatureExtractor {

	class Extractor
	{
        Sniffer *sniffer;
        Config config;
        bool is_running_live;
        volatile bool temination_requested;
	public:
        Extractor(Config config);
        ~Extractor();

        void start();
        void stop();
	};
}
