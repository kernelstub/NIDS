#pragma once

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <memory>
#include <chrono>
#include <thread>
#include <nlohmann/json.hpp>
#include "../../src/threat_intel/ThreatComponents.hpp"
#include "../../src/threat_intel/ThreatIntelligence.hpp"

class MockThreatMLModel : public ThreatMLModel {
public:
    MOCK_METHOD(double, predictThreatScore, (const ThreatIndicator&), (override));
    MOCK_METHOD(torch::Tensor, extractFeatures, (const ThreatIndicator&), (override));
};

class MockSIEMIntegration : public SIEMIntegration {
public:
    MOCK_METHOD(void, pushAlert, (const std::string&), (override));
    MOCK_METHOD(bool, validateConnection, (), (override));
};

class MockThreatHunter : public ThreatHunter {
public:
    MOCK_METHOD(std::vector<ThreatIndicator>, hunt, (const std::string&, const std::unordered_map<std::string, std::unordered_map<std::string, ThreatIndicator>>&), (override));
};

class ThreatIntelligenceTest : public ::testing::Test {
protected:
    void SetUp() override {
        nlohmann::json config = {
            {"model_path", "models/threat_model.pt"},
            {"input_size", 64}
        };
        threat_intel_ = std::make_unique<ThreatIntelligence>(config);
    }

    std::unique_ptr<ThreatIntelligence> threat_intel_;
};

TEST_F(ThreatIntelligenceTest, ProcessIndicatorWithEnrichment) {
    ThreatIndicator indicator{
        "malware",
        "high",
        {"hash": "abc123", "type": "ransomware", "campaign": "DarkSide"},
        std::chrono::system_clock::now()
    };

    auto result = threat_intel_->processIndicator(indicator);
    ASSERT_TRUE(result.has_value());
    EXPECT_GT(result->confidence_score, 0.7);
    EXPECT_TRUE(result->enriched_data.contains("campaign_details"));
    EXPECT_TRUE(result->enriched_data.contains("infrastructure_map"));
}

TEST_F(ThreatIntelligenceTest, AdvancedThreatCorrelation) {
    std::vector<ThreatIndicator> indicators = {
        {"malware", "high", {"hash": "abc123", "campaign": "DarkSide"}, std::chrono::system_clock::now()},
        {"c2", "critical", {"ip": "192.168.1.1", "campaign": "DarkSide"}, std::chrono::system_clock::now()},
        {"exploit", "high", {"cve": "CVE-2023-1234", "target": "Windows"}, std::chrono::system_clock::now()}
    };
    
    auto correlated = threat_intel_->correlateThreats(indicators);
    ASSERT_FALSE(correlated.empty());
    EXPECT_GE(correlated.size(), 2);
    EXPECT_TRUE(correlated[0].attributes.contains("correlation_strength"));
    EXPECT_TRUE(correlated[0].attributes.contains("campaign_association"));
}

TEST_F(ThreatIntelligenceTest, AdvancedCacheManagement) {
    ThreatIndicator indicator{
        "phishing",
        "medium",
        {"url": "example.com", "campaign": "PhishingCampaign2023"},
        std::chrono::system_clock::now()
    };

    threat_intel_->cacheIndicator("test_key", indicator);
    
    std::this_thread::sleep_for(std::chrono::seconds(1));
    auto cached = threat_intel_->getCachedIndicator("test_key");
    ASSERT_TRUE(cached.has_value());
    EXPECT_EQ(cached->type, "phishing");
    
    threat_intel_->invalidateCache();
    auto invalidated = threat_intel_->getCachedIndicator("test_key");
    EXPECT_FALSE(invalidated.has_value());
}

class ThreatMLModelTest : public ::testing::Test {
protected:
    void SetUp() override {
        nlohmann::json config = {
            {"model_path", "models/threat_model.pt"},
            {"input_size", 64}
        };
        model_ = std::make_unique<ThreatMLModel>(config);
    }

    std::unique_ptr<ThreatMLModel> model_;
};

TEST_F(ThreatMLModelTest, AdvancedThreatPrediction) {
    ThreatIndicator indicator{
        "exploit",
        "critical",
        {"cve": "CVE-2023-1234", "exploit_maturity": "wild", "affected_systems": "windows,linux"},
        std::chrono::system_clock::now()
    };

    double score = model_->predictThreatScore(indicator);
    EXPECT_GE(score, 0.8);
    EXPECT_LE(score, 1.0);
    
    auto features = model_->extractFeatures(indicator);
    EXPECT_EQ(features.sizes()[0], 64);
}

TEST_F(ThreatMLModelTest, ModelPerformance) {
    std::vector<ThreatIndicator> batch_indicators;
    for(int i = 0; i < 100; i++) {
        batch_indicators.push_back(ThreatIndicator{
            "malware",
            "high",
            {"hash": "hash_" + std::to_string(i)},
            std::chrono::system_clock::now()
        });
    }

    auto start = std::chrono::high_resolution_clock::now();
    for(const auto& ind : batch_indicators) {
        model_->predictThreatScore(ind);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    EXPECT_LT(duration.count(), 5000);
}

TEST_F(ThreatIntelligenceTest, ThreatHuntingIntegration) {
    auto mock_hunter = std::make_shared<MockThreatHunter>();
    threat_intel_->setThreatHunter(mock_hunter);

    std::vector<ThreatIndicator> expected_findings = {
        {"malware", "high", {"hash": "found_hash_1"}, std::chrono::system_clock::now()},
        {"c2", "critical", {"ip": "found_ip_1"}, std::chrono::system_clock::now()}
    };

    EXPECT_CALL(*mock_hunter, hunt(testing::_, testing::_))
        .WillOnce(testing::Return(expected_findings));

    auto findings = threat_intel_->huntThreats("target_system");
    EXPECT_EQ(findings.size(), expected_findings.size());
}

TEST_F(ThreatIntelligenceTest, SIEMIntegration) {
    auto mock_siem = std::make_shared<MockSIEMIntegration>();
    threat_intel_->setSIEMIntegration(mock_siem);

    EXPECT_CALL(*mock_siem, validateConnection())
        .WillOnce(testing::Return(true));

    EXPECT_CALL(*mock_siem, pushAlert(testing::_))
        .Times(1);

    ThreatIndicator critical_indicator{
        "ransomware",
        "critical",
        {"hash": "critical_hash", "campaign": "EmergingThreat"},
        std::chrono::system_clock::now()
    };

    threat_intel_->processIndicator(critical_indicator);
}
