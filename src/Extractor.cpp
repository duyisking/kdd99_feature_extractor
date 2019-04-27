#include <iostream>
#include <assert.h>

#include "Extractor.h"
#include "IpReassembler.h"
#include "ConversationReconstructor.h"
#include "StatsEngine.h"

namespace FeatureExtractor {

    Extractor::Extractor(Config config)
        : config(config)
        , temination_requested(false)
    {
        if (config.get_files_count() == 0) {
            // Input from interface
            int inum = config.get_interface_num();
            if (config.should_print_filename())
                cout << "INTERFACE " << inum << endl;
            sniffer = new Sniffer(inum, &config);
            is_running_live = true;
        }
        else {
            // Input from files
            int count = config.get_files_count();
            char **files = config.get_files_values();
            for (int i = 0; i < count; i++) {
                if (config.should_print_filename())
                    cout << "FILE '" << files[i] << "'" << endl;

                sniffer = new Sniffer(files[i], &config);
            }
            is_running_live = false;
        }
    }

    Extractor::~Extractor()
	{
        delete sniffer;
	}

	void Extractor::start()
    {
        IpReassembler reasm(config);
        ConversationReconstructor conv_reconstructor(config);
        StatsEngine stats_engine(&config);

        bool has_more_traffic = true;
        while (!temination_requested && (has_more_traffic || is_running_live)) {

            // Get frame from sniffer
            IpFragment *frag = sniffer->next_frame();
            has_more_traffic = (frag != NULL);

            Timestamp now = Timestamp();
            conv_reconstructor.report_time(now);

            Packet *datagr = nullptr;
            if (has_more_traffic) {
                // Do some assertion about the type of packet just to be sure
                // If sniffer's filter fails to fulfill this assertion, "continue" can be used here
                eth_field_type_t eth_type = frag->get_eth_type();
                ip_field_protocol_t ip_proto = frag->get_ip_proto();
                assert((eth_type == IPV4 && (ip_proto == TCP || ip_proto == UDP || ip_proto == ICMP))
                    && "Sniffer returned packet that is not (TCP or UDP or ICMP)");

                now = frag->get_end_ts();

                // IP Reassembly, frag must not be used after this
                datagr = reasm.reassemble(frag);

                // Conversation reconstruction
                if (datagr) {
                    conv_reconstructor.add_packet(datagr);
                }
            }

            // Output timedout conversations 
            Conversation *conv;
            while ((conv = conv_reconstructor.get_next_conversation()) != nullptr) {
                ConversationFeatures *cf = stats_engine.calculate_features(conv);
                conv = nullptr;		// Should not be used anymore, object will commit suicide

                cf->print(config.should_print_extra_features());
                delete cf;
            }
        }

        // If no more traffic, finish everything
        conv_reconstructor.finish_all_conversations();

        // Output leftover conversations
        Conversation *conv;
        while ((conv = conv_reconstructor.get_next_conversation()) != nullptr) {
            ConversationFeatures *cf = stats_engine.calculate_features(conv);
            conv = nullptr;

            cf->print(config.should_print_extra_features());
            delete cf;
        }
    }

    void Extractor::stop() {
        temination_requested = true;
    }

}
