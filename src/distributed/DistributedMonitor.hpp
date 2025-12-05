#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <zmq.hpp>

class DistributedMonitor {
public:
    struct MonitorNode {
        std::string node_id;
        std::string address;
        std::string status;
        std::chrono::system_clock::time_point last_heartbeat;
        nlohmann::json metrics;
    };

    struct AlertMessage {
        std::string source_node;
        std::string alert_type;
        std::string severity;
        nlohmann::json data;
        std::chrono::system_clock::time_point timestamp;
    };

    explicit DistributedMonitor(const nlohmann::json& config)
        : config_(config),
          context_(1),
          publisher_(context_, zmq::socket_type::pub),
          subscriber_(context_, zmq::socket_type::sub),
          running_(false) {
        initializeNetwork();
    }

    void start() {
        running_ = true;
        heartbeat_thread_ = std::thread(&DistributedMonitor::heartbeatLoop, this);
        message_thread_ = std::thread(&DistributedMonitor::messageLoop, this);
    }

    void stop() {
        running_ = false;
        if (heartbeat_thread_.joinable()) heartbeat_thread_.join();
        if (message_thread_.joinable()) message_thread_.join();
    }

    void broadcastAlert(const AlertMessage& alert) {
        std::lock_guard<std::mutex> lock(mutex_);
        nlohmann::json message = {
            {"type", "alert"},
            {"source", node_id_},
            {"alert_type", alert.alert_type},
            {"severity", alert.severity},
            {"data", alert.data},
            {"timestamp", std::chrono::system_clock::to_time_t(alert.timestamp)}
        };

        zmq::message_t zmq_msg(message.dump());
        publisher_.send(zmq_msg, zmq::send_flags::none);
    }

    std::vector<MonitorNode> getActiveNodes() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<MonitorNode> active_nodes;
        auto now = std::chrono::system_clock::now();

        for (const auto& [id, node] : nodes_) {
            if (now - node.last_heartbeat < heartbeat_timeout_) {
                active_nodes.push_back(node);
            }
        }

        return active_nodes;
    }

    void updateMetrics(const nlohmann::json& metrics) {
        std::lock_guard<std::mutex> lock(mutex_);
        local_metrics_ = metrics;
    }

private:
    void initializeNetwork() {
        const auto& network_config = config_["distributed"];
        node_id_ = network_config["node_id"].get<std::string>();
        heartbeat_interval_ = std::chrono::seconds(
            network_config.value("heartbeat_interval_seconds", 5));
        heartbeat_timeout_ = std::chrono::seconds(
            network_config.value("heartbeat_timeout_seconds", 15));

        // Setup ZMQ publisher
        std::string pub_address = network_config["publish_address"].get<std::string>();
        publisher_.bind(pub_address);

        // Setup ZMQ subscriber
        const auto& peers = network_config["peers"];
        for (const auto& peer : peers) {
            subscriber_.connect(peer.get<std::string>());
        }
        subscriber_.set(zmq::sockopt::subscribe, "");
    }

    void heartbeatLoop() {
        while (running_) {
            sendHeartbeat();
            std::this_thread::sleep_for(heartbeat_interval_);
        }
    }

    void messageLoop() {
        while (running_) {
            zmq::message_t message;
            if (subscriber_.recv(message, zmq::recv_flags::none)) {
                try {
                    processMessage(message);
                } catch (const std::exception& e) {
                    spdlog::error("Failed to process message: {}", e.what());
                }
            }
        }
    }

    void sendHeartbeat() {
        std::lock_guard<std::mutex> lock(mutex_);
        nlohmann::json heartbeat = {
            {"type", "heartbeat"},
            {"node_id", node_id_},
            {"timestamp", std::chrono::system_clock::to_time_t(
                std::chrono::system_clock::now())},
            {"metrics", local_metrics_}
        };

        zmq::message_t zmq_msg(heartbeat.dump());
        publisher_.send(zmq_msg, zmq::send_flags::none);
    }

    void processMessage(const zmq::message_t& zmq_msg) {
        std::string msg_str(static_cast<char*>(zmq_msg.data()), zmq_msg.size());
        nlohmann::json message = nlohmann::json::parse(msg_str);

        std::lock_guard<std::mutex> lock(mutex_);
        std::string source_node = message["node_id"].get<std::string>();

        if (message["type"] == "heartbeat") {
            updateNodeStatus(source_node, message);
        } else if (message["type"] == "alert") {
            processAlert(message);
        }
    }

    void updateNodeStatus(const std::string& node_id, const nlohmann::json& message) {
        MonitorNode& node = nodes_[node_id];
        node.node_id = node_id;
        node.status = "active";
        node.last_heartbeat = std::chrono::system_clock::now();
        node.metrics = message["metrics"];
    }

    void processAlert(const nlohmann::json& message) {
        AlertMessage alert{
            message["source"].get<std::string>(),
            message["alert_type"].get<std::string>(),
            message["severity"].get<std::string>(),
            message["data"],
            std::chrono::system_clock::from_time_t(
                message["timestamp"].get<std::time_t>())
        };

        alert_queue_.push(alert);
        alert_cv_.notify_one();
    }

    nlohmann::json config_;
    std::string node_id_;
    std::chrono::seconds heartbeat_interval_;
    std::chrono::seconds heartbeat_timeout_;

    zmq::context_t context_;
    zmq::socket_t publisher_;
    zmq::socket_t subscriber_;

    std::atomic<bool> running_;
    std::thread heartbeat_thread_;
    std::thread message_thread_;

    std::mutex mutex_;
    std::condition_variable alert_cv_;
    std::queue<AlertMessage> alert_queue_;
    std::unordered_map<std::string, MonitorNode> nodes_;
    nlohmann::json local_metrics_;
};
