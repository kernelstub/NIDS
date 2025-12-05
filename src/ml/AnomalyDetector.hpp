#pragma once

#include <vector>
#include <deque>
#include <unordered_map>
#include <memory>
#include <chrono>
#include <cmath>
#include <mutex>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <Packet.h>
#include <IpLayer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>

class AnomalyDetector {
public:
    struct NetworkMetrics {
        double packet_rate;
        double byte_rate;
        double unique_ips;
        double tcp_ratio;
        double udp_ratio;
        double avg_packet_size;
        std::chrono::system_clock::time_point timestamp;
    };

    struct BaselineProfile {
        double mean;
        double std_dev;
        double threshold;
    };

    explicit AnomalyDetector(const nlohmann::json& config)
        : config_(config),
          window_size_(std::chrono::minutes(5)),
          update_interval_(std::chrono::minutes(1)) {
        last_update_ = std::chrono::system_clock::now();
        initializeBaseline();
    }

    void processPacket(const pcpp::Packet& packet) {
        std::lock_guard<std::mutex> lock(mutex_);
        updateMetrics(packet);
        detectAnomalies();
        cleanOldMetrics();
    }

private:
    void initializeBaseline() {
        const auto& baseline_config = config_["baseline"];
        learning_period_ = std::chrono::hours(
            baseline_config.value("period_hours", 24));
        threshold_multiplier_ = baseline_config.value("threshold_multiplier", 2.0);
    }

    void updateMetrics(const pcpp::Packet& packet) {
        auto now = std::chrono::system_clock::now();
        NetworkMetrics current_metrics{};
        current_metrics.timestamp = now;

        // Update packet and byte rates
        current_metrics.packet_rate = calculatePacketRate();
        current_metrics.byte_rate = calculateByteRate(packet);

        // Update protocol ratios
        updateProtocolRatios(packet, current_metrics);

        // Update unique IPs
        updateUniqueIPs(packet);

        // Store metrics
        metrics_history_.push_back(current_metrics);
    }

    void detectAnomalies() {
        if (metrics_history_.empty()) return;

        auto now = std::chrono::system_clock::now();
        if (now - last_update_ < update_interval_) return;

        const auto& current = metrics_history_.back();
        
        // Check each metric against its baseline
        checkMetricAnomaly("packet_rate", current.packet_rate);
        checkMetricAnomaly("byte_rate", current.byte_rate);
        checkMetricAnomaly("unique_ips", current.unique_ips);
        checkMetricAnomaly("tcp_ratio", current.tcp_ratio);
        checkMetricAnomaly("udp_ratio", current.udp_ratio);

        last_update_ = now;
    }

    void checkMetricAnomaly(const std::string& metric_name, double value) {
        const auto& baseline = baselines_[metric_name];
        double z_score = (value - baseline.mean) / baseline.std_dev;

        if (std::abs(z_score) > baseline.threshold) {
            spdlog::warn("Anomaly detected in {}: value = {}, z-score = {}",
                         metric_name, value, z_score);
        }
    }

    double calculatePacketRate() {
        if (metrics_history_.empty()) return 0.0;
        auto now = std::chrono::system_clock::now();
        auto window_start = now - window_size_;
        
        int packet_count = 0;
        for (const auto& metric : metrics_history_) {
            if (metric.timestamp > window_start) packet_count++;
        }

        return static_cast<double>(packet_count) / 
               std::chrono::duration<double>(window_size_).count();
    }

    double calculateByteRate(const pcpp::Packet& packet) {
        if (metrics_history_.empty()) return 0.0;
        auto now = std::chrono::system_clock::now();
        auto window_start = now - window_size_;

        uint64_t total_bytes = 0;
        for (const auto& metric : metrics_history_) {
            if (metric.timestamp > window_start) {
                total_bytes += packet.getRawPacket()->getRawDataLen();
            }
        }

        return static_cast<double>(total_bytes) /
               std::chrono::duration<double>(window_size_).count();
    }

    void updateProtocolRatios(const pcpp::Packet& packet,
                             NetworkMetrics& metrics) {
        int total = metrics_history_.size();
        int tcp_count = 0, udp_count = 0;

        for (const auto& metric : metrics_history_) {
            if (packet.isPacketOfType(pcpp::TCP)) tcp_count++;
            if (packet.isPacketOfType(pcpp::UDP)) udp_count++;
        }

        metrics.tcp_ratio = static_cast<double>(tcp_count) / total;
        metrics.udp_ratio = static_cast<double>(udp_count) / total;
    }

    void updateUniqueIPs(const pcpp::Packet& packet) {
        if (auto* ip_layer = packet.getLayerOfType<pcpp::IPLayer>()) {
            unique_ips_.insert(ip_layer->getSrcIPAddress().toString());
            unique_ips_.insert(ip_layer->getDstIPAddress().toString());
        }
    }

    void cleanOldMetrics() {
        auto now = std::chrono::system_clock::now();
        auto threshold = now - window_size_;

        while (!metrics_history_.empty() &&
               metrics_history_.front().timestamp < threshold) {
            metrics_history_.pop_front();
        }
    }

    nlohmann::json config_;
    std::chrono::seconds window_size_;
    std::chrono::seconds update_interval_;
    std::chrono::hours learning_period_;
    double threshold_multiplier_;

    std::deque<NetworkMetrics> metrics_history_;
    std::unordered_map<std::string, BaselineProfile> baselines_;
    std::unordered_set<std::string> unique_ips_;

    std::chrono::system_clock::time_point last_update_;
    std::mutex mutex_;
};
