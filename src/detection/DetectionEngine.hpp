#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <regex>
#include <Packet.h>
#include <IpLayer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <HttpLayer.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

class DetectionEngine {
public:
    explicit DetectionEngine(const nlohmann::json& config) : config_(config) {
        initializeRules();
    }

    void analyzePacket(pcpp::RawPacket* raw_packet) {
        pcpp::Packet parsed_packet(raw_packet);

        // Check for various attack types
        if (config_["signature_based"].value("enabled", true)) {
            checkPortScan(parsed_packet);
            checkSynFlood(parsed_packet);
            checkSqlInjection(parsed_packet);
        }

        if (config_["anomaly_based"].value("enabled", true)) {
            checkAnomalies(parsed_packet);
        }
    }

private:
    void initializeRules() {
        if (const auto& sql_config = config_["signature_based"]["sql_injection"]; 
            sql_config.value("enabled", true)) {
            for (const auto& pattern : sql_config["patterns"]) {
                sql_patterns_.emplace_back(pattern.get<std::string>());
            }
        }
    }
    
    void checkPortScan(const pcpp::Packet& packet) {
        if (auto* tcp_layer = packet.getLayerOfType<pcpp::TcpLayer>()) {
            const auto& config = config_["signature_based"]["port_scan"];
            const auto threshold = config.value("threshold", 100);
            const auto window = config.value("time_window_seconds", 60);

            std::string source_ip = packet.getLayerOfType<pcpp::IPLayer>()->getSrcIPAddress().toString();
            auto now = std::chrono::steady_clock::now();

            // Clean old entries
            cleanOldEntries(port_scan_attempts_, window);

            // Update scan attempts
            port_scan_attempts_[source_ip].push_back(now);

            if (port_scan_attempts_[source_ip].size() > threshold) {
                spdlog::warn("Possible port scan detected from IP: {}", source_ip);
            }
        }
    }

    void checkSynFlood(const pcpp::Packet& packet) {
        if (auto* tcp_layer = packet.getLayerOfType<pcpp::TcpLayer>()) {
            if (tcp_layer->getTcpHeader()->synFlag) {
                const auto& config = config_["signature_based"]["syn_flood"];
                const auto threshold = config.value("threshold", 1000);
                const auto window = config.value("time_window_seconds", 60);

                std::string source_ip = packet.getLayerOfType<pcpp::IPLayer>()->getSrcIPAddress().toString();
                auto now = std::chrono::steady_clock::now();

                // Clean old entries
                cleanOldEntries(syn_flood_attempts_, window);

                // Update SYN attempts
                syn_flood_attempts_[source_ip].push_back(now);

                if (syn_flood_attempts_[source_ip].size() > threshold) {
                    spdlog::warn("Possible SYN flood attack detected from IP: {}", source_ip);
                }
            }
        }
    }

    void checkSqlInjection(const pcpp::Packet& packet) {
        if (auto* http_layer = packet.getLayerOfType<pcpp::HttpRequestLayer>()) {
            std::string payload = http_layer->getFieldByName(PCPP_HTTP_CONTENT_ENCODING)->getFieldValue();
            
            for (const auto& pattern : sql_patterns_) {
                if (std::regex_search(payload, pattern)) {
                    spdlog::warn("Possible SQL injection attempt detected in HTTP payload");
                    break;
                }
            }
        }
    }

    void checkAnomalies(const pcpp::Packet& packet) {
        // Implement anomaly detection logic here
        // This could involve statistical analysis or machine learning
    }

    template<typename T>
    void cleanOldEntries(std::unordered_map<std::string, std::vector<T>>& attempts_map, int window_seconds) {
        auto now = std::chrono::steady_clock::now();
        for (auto& [ip, timestamps] : attempts_map) {
            timestamps.erase(
                std::remove_if(timestamps.begin(), timestamps.end(),
                    [&](const auto& timestamp) {
                        return std::chrono::duration_cast<std::chrono::seconds>(now - timestamp).count() > window_seconds;
                    }),
                timestamps.end());
        }
    }

    nlohmann::json config_;
    std::vector<std::regex> sql_patterns_;
    std::unordered_map<std::string, std::vector<std::chrono::steady_clock::time_point>> port_scan_attempts_;
    std::unordered_map<std::string, std::vector<std::chrono::steady_clock::time_point>> syn_flood_attempts_;
};
