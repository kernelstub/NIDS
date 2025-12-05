#pragma once

#include <gtest/gtest.h>
#include <memory>
#include <chrono>
#include <nlohmann/json.hpp>
#include "../../src/core/ConfigManager.hpp"
#include "../../src/detection/DetectionEngine.hpp"
#include "../../src/threat_intel/ThreatIntelligence.hpp"
#include "../../src/incident_response/AutomatedResponse.hpp"

class SystemIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        nlohmann::json config = loadTestConfig();
        config_manager_ = std::make_unique<ConfigManager>(config);
        detection_engine_ = std::make_unique<DetectionEngine>(config);
        threat_intel_ = std::make_unique<ThreatIntelligence>(config);
        response_system_ = std::make_unique<AutomatedResponse>(config);
    }

    nlohmann::json loadTestConfig() {
        return nlohmann::json({
            {"detection_threshold", 0.75},
            {"model_path", "models/threat_model.pt"},
            {"input_size", 64},
            {"response_rules", nlohmann::json::array()}
        });
    }

    std::unique_ptr<ConfigManager> config_manager_;
    std::unique_ptr<DetectionEngine> detection_engine_;
    std::unique_ptr<ThreatIntelligence> threat_intel_;
    std::unique_ptr<AutomatedResponse> response_system_;
};

TEST_F(SystemIntegrationTest, DetectionToResponseFlow) {
    // Simulate network traffic
    std::vector<PacketData> test_packets = generateTestPackets();
    
    // Process through detection engine
    auto alerts = detection_engine_->processPackets(test_packets);
    ASSERT_FALSE(alerts.empty());

    // Verify threat intelligence processing
    for (const auto& alert : alerts) {
        auto enriched = threat_intel_->processIndicator(alert);
        EXPECT_TRUE(enriched.has_value());

        // Verify automated response
        response_system_->handleIncident(enriched->type, enriched->attributes);
    }
}

TEST_F(SystemIntegrationTest, ConfigurationPropagation) {
    // Verify configuration changes propagate correctly
    nlohmann::json updated_config = loadTestConfig();
    updated_config["detection_threshold"] = 0.85;

    config_manager_->updateConfig(updated_config);
    
    // Verify components received updated configuration
    EXPECT_EQ(detection_engine_->getThreshold(), 0.85);
}

TEST_F(SystemIntegrationTest, ThreatCorrelationFlow) {
    // Test threat correlation across components
    std::vector<ThreatIndicator> indicators = generateTestIndicators();
    
    // Process through threat intelligence
    auto correlated = threat_intel_->correlateThreats(indicators);
    EXPECT_FALSE(correlated.empty());

    // Verify response system handles correlated threats
    for (const auto& threat : correlated) {
        response_system_->handleIncident("correlated_threat", threat.attributes);
    }
}

private:
std::vector<PacketData> generateTestPackets() {
    // Generate test network packets
    return std::vector<PacketData>();
}

std::vector<ThreatIndicator> generateTestIndicators() {
    // Generate test threat indicators
    return std::vector<ThreatIndicator>();
}
