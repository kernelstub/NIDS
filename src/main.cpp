#include <iostream>
#include <memory>
#include <string>
#include <PcapLiveDevice.h>
#include <PcapLiveDeviceList.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <nlohmann/json.hpp>
#include "core/ConfigManager.hpp"
#include "core/PacketCapture.hpp"
#include "detection/DetectionEngine.hpp"
#include "logging/Logger.hpp"

using json = nlohmann::json;

int main(int argc, char* argv[]) {
    try {
        // Initialize logging
        auto logger = spdlog::rotating_logger_mt("nids_logger", "logs/nids.log", 1024 * 1024 * 100, 10);
        spdlog::set_default_logger(logger);
        spdlog::set_level(spdlog::level::info);
        
        spdlog::info("Starting Network Intrusion Detection System...");

        // Load configuration
        ConfigManager config_manager("config/nids_config.json");
        auto config = config_manager.getConfig();

        // Initialize packet capture
        auto packet_capture = std::make_unique<PacketCapture>(config["network"]);
        
        // Initialize detection engine
        auto detection_engine = std::make_unique<DetectionEngine>(config["detection"]);

        // Start monitoring
        packet_capture->startCapture([&detection_engine](pcpp::RawPacket* packet) {
            detection_engine->analyzePacket(packet);
        });

        // Wait for user input to stop
        std::cout << "Press Enter to stop monitoring..." << std::endl;
        std::cin.get();

        // Cleanup
        packet_capture->stopCapture();
        spdlog::info("NIDS stopped successfully");

        return 0;
    } catch (const std::exception& e) {
        spdlog::error("Fatal error: {}", e.what());
        return 1;
    }
}
