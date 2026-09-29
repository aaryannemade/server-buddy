#pragma once

#include <array>
#include <cstdint>

#include "esphome/components/espnow/espnow_component.h"
#include "esphome/components/sensor/sensor.h"
#include "esphome/core/component.h"
#include "sb_crypto.h"
#include "sb_protocol.h"

namespace esphome::server_buddy {

// Receive-only Server Buddy radio protocol v1 for an always-on USB-powered node.
// ESPHome owns ESP-NOW callback queues; this component runs only on the main loop.
class ServerBuddyNode : public Component, public espnow::ESPNowReceivedPacketHandler {
 public:
  void set_espnow(espnow::ESPNowComponent *radio) { this->radio_ = radio; }
  void set_hub_mac(const std::array<uint8_t, 6> &mac) { this->hub_mac_ = mac; }
  void set_node_key(const std::array<uint8_t, 16> &key) { this->node_key_ = key; }
  void set_temperature_sensor(sensor::Sensor *sensor) { this->temperature_ = sensor; }
  void set_humidity_sensor(sensor::Sensor *sensor) { this->humidity_ = sensor; }
  void set_illuminance_sensor(sensor::Sensor *sensor) { this->illuminance_ = sensor; }

  void setup() override;
  void loop() override;
  void dump_config() override;
  float get_setup_priority() const override { return setup_priority::LATE - 1.0f; }
  bool on_receive(const espnow::ESPNowRecvInfo &info, const uint8_t *data, uint8_t size) override;

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
  void send_state_();
  bool begin_frame_(sb_frame_t &frame, Pending kind);
  void retransmit_();
  void failed_frame_();
  void forget_pending_pair_();
  void build_schema_();

  espnow::ESPNowComponent *radio_{nullptr};
  sensor::Sensor *temperature_{nullptr};
  sensor::Sensor *humidity_{nullptr};
  sensor::Sensor *illuminance_{nullptr};
  std::array<uint8_t, 6> hub_mac_{};
  std::array<uint8_t, 16> node_key_{};
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
  uint32_t pending_seq_{0}, pending_boot_{0}, last_send_ms_{0}, next_report_ms_{0};
  uint32_t next_pair_ms_{0}, confirm_after_ms_{0}, next_hello_ms_{0};
  uint8_t attempts_{0};
};

}  // namespace esphome::server_buddy
