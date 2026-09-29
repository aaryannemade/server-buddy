#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "esphome/components/binary_sensor/binary_sensor.h"
#include "esphome/components/espnow/espnow_component.h"
#include "esphome/components/sensor/sensor.h"
#include "esphome/components/text_sensor/text_sensor.h"
#include "esphome/core/component.h"
#include "esphome/core/version.h"
#include "sb_crypto.h"
#include "sb_protocol.h"

namespace esphome::server_buddy {

// ESPHome 2026.7 widened ESP-NOW receive sizes for opt-in v2 payloads.
// Server Buddy still caps frames at 250 bytes; match the handler's ABI.
#if ESPHOME_VERSION_CODE >= VERSION_CODE(2026, 7, 0)
using ReceiveSize = uint16_t;
#else
using ReceiveSize = uint8_t;
#endif

// Receive-only Server Buddy radio protocol v1 for an always-on node.
// ESPHome owns ESP-NOW callback queues; this component runs only on the main loop.
class ServerBuddyNode : public Component, public espnow::ESPNowReceivedPacketHandler {
 public:
  void set_espnow(espnow::ESPNowComponent *radio) { this->radio_ = radio; }
  void set_hub_mac(const std::array<uint8_t, 6> &mac) { this->hub_mac_ = mac; }
  void set_node_key(const std::array<uint8_t, 16> &key) { this->node_key_ = key; }
  void set_report_interval(uint32_t seconds) { this->report_ms_ = seconds * 1000; }
  void set_boot_event_number(uint8_t number) { this->boot_number_ = number; }
  void set_node_info(const char *name, const char *model, const char *fw) {
    this->node_name_ = name;
    this->model_ = model;
    this->fw_version_ = fw;
  }
  // Metadata strings are codegen literals and outlive the component.
  void add_sensor(sensor::Sensor *s, uint8_t number, const char *object_id, const char *name, const char *unit,
                  const char *device_class, uint8_t state_class, int8_t accuracy, uint8_t flags);
  void add_binary_sensor(binary_sensor::BinarySensor *s, uint8_t number, const char *object_id, const char *name,
                         const char *unit, const char *device_class, uint8_t state_class, int8_t accuracy,
                         uint8_t flags);
  void add_text_sensor(text_sensor::TextSensor *s, uint8_t number, const char *object_id, const char *name,
                       const char *unit, const char *device_class, uint8_t state_class, int8_t accuracy,
                       uint8_t flags);

  void setup() override;
  void loop() override;
  void dump_config() override;
  float get_setup_priority() const override { return setup_priority::LATE - 1.0f; }
  bool on_receive(const espnow::ESPNowRecvInfo &info, const uint8_t *data, ReceiveSize size) override;

 protected:
  enum class Pending : uint8_t { NONE, HELLO, DESCRIBE, BOOT_EVENT, STATE };
  struct Session {
    uint8_t version;
    uint8_t epoch;
    uint8_t key_id[SB_KEY_ID_LEN];
    uint8_t hub_mac[6];
    uint8_t lmk[SB_LMK_LEN];
    uint8_t k_mic[SB_KMIC_LEN];
  };
  struct Entity {
    uint8_t platform;  // 1 sensor, 2 binary_sensor, 3 text_sensor
    uint8_t number;
    const char *object_id, *name, *unit, *device_class;
    uint8_t state_class;
    int8_t accuracy;
    uint8_t flags;
    void *source;  // sensor::Sensor* / binary_sensor::BinarySensor* / text_sensor::TextSensor*
    bool dirty;     // needs sending; cleared when packed, re-set if that frame fails
    uint32_t last;  // text sensors: hash of the last value, to ignore identical republishes
  };

  void add_entity_(uint8_t platform, void *source, uint8_t number, const char *object_id, const char *name,
                   const char *unit, const char *device_class, uint8_t state_class, int8_t accuracy, uint8_t flags);
  bool load_session_();
  bool store_session_();
  bool increment_boot_();
  bool install_peer_(bool encrypted);
  void send_pair_request_();
  void handle_pair_response_(const uint8_t *data, size_t len, const sb_frame_t &frame);
  void handle_ack_(const uint8_t *data, size_t len, const sb_frame_t &frame);
  void send_hello_();
  void send_describe_();
  void send_boot_event_();
  bool send_state_batch_();
  bool begin_frame_(sb_frame_t &frame, Pending kind);
  void retransmit_();
  void failed_frame_();
  void forget_pending_pair_();
  void build_schema_();
  size_t value_(const Entity &entity, sb_value_t &value, char *text, size_t cap) const;

  espnow::ESPNowComponent *radio_{nullptr};
  std::vector<Entity> entities_;
  const char *node_name_{""}, *model_{""}, *fw_version_{""};
  std::array<uint8_t, 6> hub_mac_{};
  std::array<uint8_t, 16> node_key_{};
  uint32_t report_ms_{60000};
  uint8_t node_mac_[6]{};
  uint8_t key_id_[SB_KEY_ID_LEN]{};
  uint8_t nonce_[SB_NONCE_LEN]{};
  uint8_t lmk_[SB_LMK_LEN]{};
  uint8_t k_mic_[SB_KMIC_LEN]{};
  uint8_t epoch_{0};
  uint32_t boot_{0}, origin_boot_{0}, seq_{0};
  bool paired_{false}, pair_confirming_{false}, hello_done_{false};
  bool need_describe_{false}, boot_event_acked_{false};
  uint8_t describe_index_{0}, describe_count_{0}, schema_blob_[SB_MAX_SCHEMA]{};
  size_t schema_len_{0};
  uint32_t schema_hash_{0};
  Pending pending_{Pending::NONE};
  uint8_t frame_[SB_MAX_FRAME]{};
  size_t frame_len_{0};
  // Entities carried by the STATE frame in flight.
  std::vector<uint8_t> batch_;
  uint8_t boot_number_{255};
  // Send back-off after a failure. A flag, not just a deadline: comparing a
  // stale deadline with millis() goes wrong after ~24.8 days of uptime.
  bool backoff_{false};
  uint32_t pending_seq_{0}, pending_boot_{0}, last_send_ms_{0}, next_report_ms_{0}, retry_after_ms_{0};
  uint32_t next_pair_ms_{0}, confirm_after_ms_{0}, next_hello_ms_{0};
  uint8_t attempts_{0};
};

}  // namespace esphome::server_buddy
