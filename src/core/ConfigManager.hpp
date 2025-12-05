#pragma once

#include <string>
#include <nlohmann/json.hpp>
#include <fstream>
#include <stdexcept>
#include <spdlog/spdlog.h>

class ConfigManager {
public:
    explicit ConfigManager(const std::string& config_path) {
        try {
            std::ifstream config_file(config_path);
            if (!config_file.is_open()) {
                throw std::runtime_error("Unable to open config file: " + config_path);
            }
            config_file >> config;
        } catch (const nlohmann::json::parse_error& e) {
            spdlog::error("Failed to parse config file: {}", e.what());
            throw;
        }
    }

    const nlohmann::json& getConfig() const {
        return config;
    }

    template<typename T>
    T getValue(const std::string& key, const T& default_value) const {
        try {
            return config.value<T>(key, default_value);
        } catch (const std::exception& e) {
            spdlog::warn("Failed to get config value for key {}: {}", key, e.what());
            return default_value;
        }
    }

private:
    nlohmann::json config;
};
