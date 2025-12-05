#pragma once

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

// Network Traffic Visualizer
class NetworkVisualizer {
public:
    struct VisualizationConfig {
        bool show_protocols;
        bool show_geo_data;
        bool show_threat_indicators;
        int update_interval_ms;
    };

    explicit NetworkVisualizer(const nlohmann::json& config) {
        loadVisualizationConfig(config);
    }

    void updateTrafficData(const std::vector<PacketData>& packets) {
        std::lock_guard<std::mutex> lock(data_mutex_);
        processNewPackets(packets);
        updateVisualization();
    }

    nlohmann::json generateVisualizationData() {
        std::lock_guard<std::mutex> lock(data_mutex_);
        return createVisualizationPayload();
    }

private:
    VisualizationConfig config_;
    std::mutex data_mutex_;
    std::unordered_map<std::string, NetworkNode> nodes_;
    std::vector<NetworkConnection> connections_;

    void loadVisualizationConfig(const nlohmann::json& config) {
        config_.show_protocols = config["show_protocols"].get<bool>();
        config_.show_geo_data = config["show_geo_data"].get<bool>();
        config_.show_threat_indicators = config["show_threat_indicators"].get<bool>();
        config_.update_interval_ms = config["update_interval_ms"].get<int>();
    }

    void processNewPackets(const std::vector<PacketData>& packets) {
        for (const auto& packet : packets) {
            updateNetworkGraph(packet);
            updateTrafficStatistics(packet);
        }
    }

    void updateNetworkGraph(const PacketData& packet) {
        // Update network topology and connection information
    }

    void updateTrafficStatistics(const PacketData& packet) {
        // Update traffic statistics and metrics
    }

    void updateVisualization() {
        // Refresh visualization data
    }

    nlohmann::json createVisualizationPayload() {
        // Generate visualization data in JSON format
        nlohmann::json payload;
        // Add visualization data
        return payload;
    }
};

// Real-time Traffic Analyzer
class TrafficAnalyzer {
public:
    struct AnalysisMetrics {
        double bandwidth_usage;
        int active_connections;
        std::unordered_map<std::string, int> protocol_distribution;
        std::vector<std::string> anomalies;
    };

    void analyzeTraffic(const std::vector<PacketData>& packets) {
        updateMetrics(packets);
        detectAnomalies();
    }

    AnalysisMetrics getMetrics() const {
        return current_metrics_;
    }

private:
    AnalysisMetrics current_metrics_;

    void updateMetrics(const std::vector<PacketData>& packets) {
        // Update traffic analysis metrics
    }

    void detectAnomalies() {
        // Implement anomaly detection logic
    }
};

// Geo-location Mapping
class GeoMapper {
public:
    explicit GeoMapper(const std::string& geo_db_path) {
        loadGeoDatabase(geo_db_path);
    }

    std::optional<GeoLocation> getLocation(const std::string& ip_address) {
        // Implement IP to geo-location mapping
        return std::nullopt;
    }

private:
    void loadGeoDatabase(const std::string& path) {
        // Load geo-location database
    }
};
