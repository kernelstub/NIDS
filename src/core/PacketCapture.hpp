#pragma once

#include <functional>
#include <memory>
#include <string>
#include <PcapLiveDevice.h>
#include <PcapLiveDeviceList.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

class PacketCapture {
public:
    explicit PacketCapture(const nlohmann::json& config) {
        std::string interface_name = config.value("interface", "any");
        pcpp::PcapLiveDevice* dev = nullptr;

        if (interface_name == "any") {
            dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp("0.0.0.0");
        } else {
            dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interface_name);
        }

        if (dev == nullptr) {
            throw std::runtime_error("Could not find network interface");
        }

        device.reset(dev);
        device->open();

        if (config.value("promiscuous_mode", true)) {
            device->setPromiscuous(true);
        }

        if (config["filter"].value("enabled", true)) {
            std::string filter_expr;
            const auto& protocols = config["filter"]["protocols"];
            for (const auto& protocol : protocols) {
                if (!filter_expr.empty()) filter_expr += " or ";
                filter_expr += protocol.get<std::string>();
            }
            device->setFilter(filter_expr);
        }
    }

    void startCapture(std::function<void(pcpp::RawPacket*)> callback) {
        if (!device || !device->isOpened()) {
            throw std::runtime_error("Device not initialized or opened");
        }

        device->startCapture([callback](pcpp::RawPacket* packet) {
            callback(packet);
            return true;
        });

        spdlog::info("Started packet capture on interface {}", device->getName());
    }

    void stopCapture() {
        if (device && device->isOpened()) {
            device->stopCapture();
            device->close();
            spdlog::info("Stopped packet capture on interface {}", device->getName());
        }
    }

    ~PacketCapture() {
        stopCapture();
    }

private:
    std::unique_ptr<pcpp::PcapLiveDevice> device;
};
