#include <iostream>
#include <new>          // std::bad_alloc
#include <csignal>

#include "Config.h"
#include "Extractor.h"

using namespace std;
using namespace FeatureExtractor;

Extractor *extractor;

void signal_handler(int signum);

int main(int argc, char **argv)
{
	// Register signal handler for termination
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
#ifdef SIGBREAK
	signal(SIGBREAK, signal_handler);
#endif

	try {
        extractor = new Extractor(argc, argv);
        extractor->start();
	}
	catch (std::bad_alloc& ba)	// Inform when memory limit reached
	{
		std::cerr << "Error allocating memory (Exception bad_alloc): " << ba.what() << '\n';
		return -1;
	}

	return 0;
}

void signal_handler(int signum)
{
	cerr << "Terminating extractor (signal " << signum << " received)" << endl;
    extractor->stop();
}
