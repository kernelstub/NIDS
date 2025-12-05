#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <chrono>
#include <ctime>
#include <mutex>
#include <queue>
#include <thread>
#include <condition_variable>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <curl/curl.h>
#include <openssl/sha.h>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/ip/tcp.hpp>

class ThreatIntelligence {
public:
    enum class ConfidenceLevel {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    };

    struct ThreatIndicator {
        std::string id;           // Unique identifier
        std::string campaign;     // Associated campaign name
        double confidence_score;  // ML-based confidence score
        ConfidenceLevel confidence_level;
        std::vector<std::string> related_indicators; // Related IoCs
        std::string tlp;         // Traffic Light Protocol level
        std::string diamond_model_status; // Attack stage in Diamond Model
        std::string type;        // IP, domain, hash, etc.
        std::string value;       // The actual indicator
        std::string source;      // Source of the intelligence
        std::string severity;    // high, medium, low
        std::string description;
        std::time_t timestamp;
        std::vector<std::string> tags;
    };

    explicit ThreatIntelligence(const nlohmann::json& config) 
        : config_(config), last_update_(std::chrono::system_clock::now()),
          worker_thread_(&ThreatIntelligence::threatHuntingWorker, this),
          rate_limiter_(config["rate_limit"].get<size_t>()),
          cache_ttl_(std::chrono::minutes(config["cache_ttl"].get<int>())),
          ml_model_(std::make_unique<ThreatMLModel>(config["ml_config"])),
          quantum_crypto_(std::make_unique<QuantumResistantCrypto>()),
          behavioral_analytics_(std::make_unique<BehavioralAnalytics>()),
          memory_forensics_(std::make_unique<MemoryForensics>()),
          zero_day_scanner_(std::make_unique<ZeroDayScanner>()),
          blockchain_sharing_(std::make_unique<BlockchainThreatSharing>()),
          traffic_analyzer_(std::make_unique<NetworkTrafficAnalyzer>()),
          malware_sandbox_(std::make_unique<MalwareSandbox>()),
          attack_predictor_(std::make_unique<AttackPredictor>()) {
        initializeFeeds();
        initializeCache();
        initializeSIEMIntegration();
        startRealTimeMonitoring();
        updateThreatData();
    }

    bool isIndicatorMalicious(const std::string& indicator_type, const std::string& value) {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto& indicators = threat_indicators_[indicator_type];
        return indicators.find(value) != indicators.end();
    }

    std::vector<ThreatIndicator> queryThreatData(const std::string& value) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ThreatIndicator> results;
        
        for (const auto& [type, indicators] : threat_indicators_) {
            if (auto it = indicators.find(value); it != indicators.end()) {
                results.push_back(it->second);
            }
        }
        
        return results;
    }

    void updateThreatData() {
        for (const auto& feed : intel_feeds_) {
            try {
                fetchThreatData(feed);
            } catch (const std::exception& e) {
                spdlog::error("Failed to update threat data from {}: {}", feed.name, e.what());
            }
        }
        last_update_ = std::chrono::system_clock::now();
    }

    std::vector<ThreatIndicator> performThreatHunting(const std::string& target) {
        std::lock_guard<std::mutex> lock(mutex_);
        return threat_hunter_->hunt(target, threat_indicators_);
    }

    void correlateThreats(const ThreatIndicator& indicator) {
        auto correlated = correlation_engine_->analyze(indicator, threat_indicators_);
        updateThreatScore(correlated);
    }

    double calculateRiskScore(const ThreatIndicator& indicator) {
        return ml_model_->predictThreatScore(indicator);
    }

    void shareIntelligence(const ThreatIndicator& indicator) {
        if (shouldShare(indicator)) {
            siem_integration_->pushAlert(formatSTIX(indicator));
        }
    }

private:
    struct IntelFeed {
        std::string authentication_method;
        std::chrono::seconds refresh_interval;
        bool requires_ssl_verification;
        std::string data_format; // STIX/TAXII/Custom
        std::string name;
        std::string url;
        std::string api_key;
        std::string type;
    };

    void initializeFeeds() {
        const auto& feeds_config = config_["feeds"];
        for (const auto& feed : feeds_config) {
            intel_feeds_.push_back({
                feed["name"].get<std::string>(),
                feed["url"].get<std::string>(),
                feed["api_key"].get<std::string>(),
                feed["type"].get<std::string>()
            });
        }
    }

    void fetchThreatData(const IntelFeed& feed) {
        CURL* curl = curl_easy_init();
        if (!curl) {
            throw std::runtime_error("Failed to initialize CURL");
        }

        struct curl_slist* headers = nullptr;
        if (!feed.api_key.empty()) {
            std::string auth_header = "Authorization: " + feed.api_key;
            headers = curl_slist_append(headers, auth_header.c_str());
        }

        std::string response_data;
        curl_easy_setopt(curl, CURLOPT_URL, feed.url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            curl_easy_cleanup(curl);
            curl_slist_free_all(headers);
            throw std::runtime_error(curl_easy_strerror(res));
        }

        parseThreatData(feed, response_data);

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }

    static size_t writeCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
        userp->append((char*)contents, size * nmemb);
        return size * nmemb;
    }

    void parseThreatData(const IntelFeed& feed, const std::string& data) {
        try {
            nlohmann::json json_data = nlohmann::json::parse(data);
            std::lock_guard<std::mutex> lock(mutex_);

            for (const auto& indicator : json_data["indicators"]) {
                ThreatIndicator ti{
                    indicator["type"].get<std::string>(),
                    indicator["value"].get<std::string>(),
                    feed.name,
                    indicator["severity"].get<std::string>(),
                    indicator["description"].get<std::string>(),
                    std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()),
                    indicator["tags"].get<std::vector<std::string>>()
                };
                threat_indicators_[ti.type][ti.value] = ti;
            }
        } catch (const std::exception& e) {
            spdlog::error("Failed to parse threat data from {}: {}", feed.name, e.what());
        }
    }

    // Advanced Components
    std::unique_ptr<ThreatMLModel> ml_model_;
    std::unique_ptr<ThreatCorrelationEngine> correlation_engine_;
    std::unique_ptr<ThreatHunter> threat_hunter_;
    std::unique_ptr<SIEMIntegration> siem_integration_;
    std::unique_ptr<ThreatCache> threat_cache_;
    std::unique_ptr<QuantumResistantCrypto> quantum_crypto_;
    std::unique_ptr<BehavioralAnalytics> behavioral_analytics_;
    std::unique_ptr<MemoryForensics> memory_forensics_;
    std::unique_ptr<ZeroDayScanner> zero_day_scanner_;
    std::unique_ptr<BlockchainThreatSharing> blockchain_sharing_;
    std::unique_ptr<NetworkTrafficAnalyzer> traffic_analyzer_;
    std::unique_ptr<MalwareSandbox> malware_sandbox_;
    std::unique_ptr<AttackPredictor> attack_predictor_;

    // Thread Management
    std::thread worker_thread_;
    std::condition_variable cv_;
    bool shutdown_{false};

    // Rate Limiting & Caching
    RateLimiter rate_limiter_;
    std::chrono::minutes cache_ttl_;
    std::unordered_map<std::string, std::chrono::system_clock::time_point> cache_expiry_;

    // Core Data
    nlohmann::json config_;
    std::vector<IntelFeed> intel_feeds_;
    std::unordered_map<std::string, std::unordered_map<std::string, ThreatIndicator>> threat_indicators_;
    std::chrono::system_clock::time_point last_update_;
    std::mutex mutex_;

    // WebSocket for Real-time Updates
    std::unique_ptr<boost::beast::websocket::stream<boost::asio::ip::tcp::socket>> ws_;
    boost::asio::io_context ioc_;
    std::thread ws_thread_;
};
