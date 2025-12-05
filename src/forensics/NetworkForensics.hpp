#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <pcap.h>
#include <Packet.h>
#include <IpLayer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <PayloadLayer.h>

class NetworkForensics {
public:
    struct ForensicEvent {
        std::string event_id;
        std::string event_type;
        std::string source_ip;
        std::string destination_ip;
        uint16_t source_port;
        uint16_t destination_port;
        std::string protocol;
        std::vector<uint8_t> payload;
        std::chrono::system_clock::time_point timestamp;
        std::string hash;
        std::vector<std::string> tags;
    };

    explicit NetworkForensics(const nlohmann::json& config)
        : config_(config),
          pcap_writer_(nullptr),
          max_events_(config.value("max_events", 10000)) {
        initializeStorage();
    }

    void capturePacket(const pcpp::Packet& packet, const std::string& event_type = "standard") {
        std::lock_guard<std::mutex> lock(mutex_);
        
        ForensicEvent event = createForensicEvent(packet, event_type);
        events_.push_back(event);

        if (config_.value("pcap_capture", true)) {
            writePacketToPcap(packet);
        }

        if (events_.size() > max_events_) {
            archiveOldEvents();
        }
    }

    std::vector<ForensicEvent> queryEvents(const std::string& filter_type,
                                         const std::string& filter_value,
                                         const std::chrono::system_clock::time_point& start_time,
                                         const std::chrono::system_clock::time_point& end_time) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ForensicEvent> results;

        for (const auto& event : events_) {
            if (event.timestamp >= start_time && event.timestamp <= end_time) {
                if (matchesFilter(event, filter_type, filter_value)) {
                    results.push_back(event);
                }
            }
        }

        return results;
    }

    void exportEvidence(const std::string& case_id,
                       const std::vector<ForensicEvent>& events) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        std::filesystem::path evidence_dir = 
            std::filesystem::path(config_["evidence_path"].get<std::string>()) / case_id;
        std::filesystem::create_directories(evidence_dir);

        // Export event metadata
        nlohmann::json evidence_metadata;
        evidence_metadata["case_id"] = case_id;
        evidence_metadata["export_time"] = 
            std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        evidence_metadata["event_count"] = events.size();

        std::ofstream metadata_file(evidence_dir / "metadata.json");
        metadata_file << evidence_metadata.dump(4);

        // Export individual events
        for (const auto& event : events) {
            exportEvent(evidence_dir, event);
        }

        spdlog::info("Exported {} events for case {}", events.size(), case_id);
    }

private:
    void initializeStorage() {
        const auto& storage_config = config_["storage"];
        std::filesystem::path storage_path = storage_config["path"].get<std::string>();
        std::filesystem::create_directories(storage_path);

        if (config_.value("pcap_capture", true)) {
            std::string pcap_file = (storage_path / "capture.pcap").string();
            pcap_writer_.reset(new pcpp::PcapFileWriterDevice(pcap_file.c_str()));
            if (!pcap_writer_->open()) {
                throw std::runtime_error("Failed to open PCAP file for writing");
            }
        }
    }

    ForensicEvent createForensicEvent(const pcpp::Packet& packet,
                                    const std::string& event_type) {
        ForensicEvent event;
        event.event_id = generateEventId();
        event.event_type = event_type;
        event.timestamp = std::chrono::system_clock::now();

        if (auto* ip_layer = packet.getLayerOfType<pcpp::IPLayer>()) {
            event.source_ip = ip_layer->getSrcIPAddress().toString();
            event.destination_ip = ip_layer->getDstIPAddress().toString();
        }

        if (auto* tcp_layer = packet.getLayerOfType<pcpp::TcpLayer>()) {
            event.protocol = "TCP";
            event.source_port = tcp_layer->getSrcPort();
            event.destination_port = tcp_layer->getDstPort();
        } else if (auto* udp_layer = packet.getLayerOfType<pcpp::UdpLayer>()) {
            event.protocol = "UDP";
            event.source_port = udp_layer->getSrcPort();
            event.destination_port = udp_layer->getDstPort();
        }

        if (auto* payload_layer = packet.getLayerOfType<pcpp::PayloadLayer>()) {
            const uint8_t* payload_data = payload_layer->getPayload();
            size_t payload_len = payload_layer->getPayloadLen();
            event.payload.assign(payload_data, payload_data + payload_len);
        }

        event.hash = calculateEventHash(event);
        return event;
    }

    void writePacketToPcap(const pcpp::Packet& packet) {
        if (pcap_writer_ && pcap_writer_->isOpened()) {
            pcap_writer_->writePacket(*(packet.getRawPacket()));
        }
    }

    void archiveOldEvents() {
        const auto& archive_config = config_["archive"];
        std::filesystem::path archive_path = archive_config["path"].get<std::string>();
        std::filesystem::create_directories(archive_path);

        std::string archive_file = (archive_path / generateArchiveFilename()).string();
        std::ofstream archive(archive_file);
        nlohmann::json archive_data;

        size_t batch_size = events_.size() / 2;
        for (size_t i = 0; i < batch_size; ++i) {
            archive_data.push_back(serializeEvent(events_[i]));
        }

        archive << archive_data.dump();
        events_.erase(events_.begin(), events_.begin() + batch_size);
    }

    bool matchesFilter(const ForensicEvent& event,
                      const std::string& filter_type,
                      const std::string& filter_value) {
        if (filter_type == "ip") {
            return event.source_ip == filter_value ||
                   event.destination_ip == filter_value;
        } else if (filter_type == "port") {
            uint16_t port = std::stoi(filter_value);
            return event.source_port == port ||
                   event.destination_port == port;
        } else if (filter_type == "protocol") {
            return event.protocol == filter_value;
        } else if (filter_type == "event_type") {
            return event.event_type == filter_value;
        }
        return false;
    }

    void exportEvent(const std::filesystem::path& dir, const ForensicEvent& event) {
        nlohmann::json event_data = serializeEvent(event);
        std::string event_file = (dir / (event.event_id + ".json")).string();
        std::ofstream event_stream(event_file);
        event_stream << event_data.dump(4);

        if (!event.payload.empty()) {
            std::string payload_file = (dir / (event.event_id + ".bin")).string();
            std::ofstream payload_stream(payload_file, std::ios::binary);
            payload_stream.write(reinterpret_cast<const char*>(event.payload.data()),
                               event.payload.size());
        }
    }

    std::string generateEventId() {
        static std::atomic<uint64_t> counter{0};
        return std::to_string(std::chrono::system_clock::to_time_t(
                   std::chrono::system_clock::now())) + 
               "_" + std::to_string(++counter);
    }

    std::string calculateEventHash(const ForensicEvent& event) {
        // Implement secure hashing of event data
        return "hash_placeholder";
    }

    std::string generateArchiveFilename() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << "archive_" << time_t << ".json";
        return ss.str();
    }

    nlohmann::json serializeEvent(const ForensicEvent& event) {
        nlohmann::json j;
        j["event_id"] = event.event_id;
        j["event_type"] = event.event_type;
        j["source_ip"] = event.source_ip;
        j["destination_ip"] = event.destination_ip;
        j["source_port"] = event.source_port;
        j["destination_port"] = event.destination_port;
        j["protocol"] = event.protocol;
        j["timestamp"] = std::chrono::system_clock::to_time_t(event.timestamp);
        j["hash"] = event.hash;
        j["tags"] = event.tags;
        return j;
    }

    nlohmann::json config_;
    std::vector<ForensicEvent> events_;
    size_t max_events_;
    std::unique_ptr<pcpp::PcapFileWriterDevice> pcap_writer_;
    std::mutex mutex_;
};
