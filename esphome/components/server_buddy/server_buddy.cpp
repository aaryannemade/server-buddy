#include "server_buddy.h"

#include <algorithm>
#include <cmath>
#include <cstring>

#include "esphome/core/log.h"

#include <esp_mac.h>
#include <esp_now.h>
#include <esp_random.h>
#include <esp_wifi.h>
#include <nvs.h>
#include <nvs_flash.h>

namespace esphome::server_buddy {

static const char *const TAG = "server_buddy";
static constexpr uint8_t BROADCAST[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static constexpr uint32_t STATE_RETRY_MS = 5000;  // back-off while the hub is unreachable
static constexpr uint32_t HELLO_RETRY_MS = 30000;  // cap: long report intervals must not delay recovery
static constexpr uint32_t ACK_TIMEOUT_MS = 500;
static constexpr uint8_t MAX_ATTEMPTS = 3;

static sb_str_t text(const char *value) {
  return {reinterpret_cast<const uint8_t *>(value), static_cast<uint8_t>(strlen(value))};
}

bool ServerBuddyNode::increment_boot_() {
  nvs_handle_t handle;
  if (nvs_open("sb_node", NVS_READWRITE, &handle) != ESP_OK) return false;
  uint32_t counter = 0;
  esp_err_t err = nvs_get_u32(handle, "boot", &counter);
  if (err == ESP_ERR_NVS_NOT_FOUND) err = ESP_OK;
  if (err == ESP_OK) {
    counter++;
    if (!counter) counter = 1;
    err = nvs_set_u32(handle, "boot", counter);
    if (err == ESP_OK) err = nvs_commit(handle);
  }
  nvs_close(handle);
  if (err != ESP_OK) return false;
  this->boot_ = counter;
  this->seq_ = 0;
  return true;
}

bool ServerBuddyNode::load_session_() {
  nvs_handle_t handle;
  if (nvs_open("sb_node", NVS_READONLY, &handle) != ESP_OK) return false;
  Session record{};
  size_t size = sizeof record;
  esp_err_t err = nvs_get_blob(handle, "session", &record, &size);
  nvs_close(handle);
  if (err != ESP_OK || size != sizeof record || record.version != 1 || !record.epoch ||
      memcmp(record.hub_mac, this->hub_mac_.data(), 6) != 0 ||
      memcmp(record.key_id, this->key_id_, SB_KEY_ID_LEN) != 0)
    return false;
  this->epoch_ = record.epoch;
  memcpy(this->lmk_, record.lmk, sizeof this->lmk_);
  memcpy(this->k_mic_, record.k_mic, sizeof this->k_mic_);
  return true;
}

bool ServerBuddyNode::store_session_() {
  Session record{};
  record.version = 1;
  record.epoch = this->epoch_;
  memcpy(record.hub_mac, this->hub_mac_.data(), 6);
  memcpy(record.key_id, this->key_id_, sizeof record.key_id);
  memcpy(record.lmk, this->lmk_, sizeof record.lmk);
  memcpy(record.k_mic, this->k_mic_, sizeof record.k_mic);
  nvs_handle_t handle;
  if (nvs_open("sb_node", NVS_READWRITE, &handle) != ESP_OK) return false;
  esp_err_t err = nvs_set_blob(handle, "session", &record, sizeof record);
  if (err == ESP_OK) err = nvs_commit(handle);
  nvs_close(handle);
  return err == ESP_OK;
}

bool ServerBuddyNode::install_peer_(bool encrypted) {
  // ESPHome keeps a known peer for its receive dispatch; update only the
  // underlying IDF peer table when switching between plaintext and LMK.
  if (this->radio_->add_peer(this->hub_mac_.data()) != ESP_OK) return false;
  esp_now_peer_info_t peer{};
  memcpy(peer.peer_addr, this->hub_mac_.data(), 6);
  peer.ifidx = WIFI_IF_STA;
  peer.channel = 0;  // use the fixed channel configured by ESPHome's espnow component
  peer.encrypt = encrypted;
  if (encrypted) memcpy(peer.lmk, this->lmk_, sizeof this->lmk_);
  return esp_now_mod_peer(&peer) == ESP_OK;
}

void ServerBuddyNode::add_entity_(uint8_t platform, void *source, uint8_t number, const char *object_id,
                                  const char *name, const char *unit, const char *device_class,
                                  uint8_t state_class, int8_t accuracy, uint8_t flags) {
  this->entities_.push_back(
      {platform, number, object_id, name, unit, device_class, state_class, accuracy, flags, source, true, 0});
}

void ServerBuddyNode::add_sensor(sensor::Sensor *s, uint8_t number, const char *object_id, const char *name,
                                 const char *unit, const char *device_class, uint8_t state_class,
                                 int8_t accuracy, uint8_t flags) {
  // Sensors are sampled at the report interval; they do not trigger reports.
  this->add_entity_(1, s, number, object_id, name, unit, device_class, state_class, accuracy, flags);
}

void ServerBuddyNode::add_binary_sensor(binary_sensor::BinarySensor *s, uint8_t number, const char *object_id,
                                        const char *name, const char *unit, const char *device_class,
                                        uint8_t state_class, int8_t accuracy, uint8_t flags) {
  size_t index = this->entities_.size();
  this->add_entity_(2, s, number, object_id, name, unit, device_class, state_class, accuracy, flags);
  // Doors, buttons and the like are reported as soon as they change.
  s->add_on_state_callback([this, index](bool) { this->entities_[index].dirty = true; });
}

void ServerBuddyNode::add_text_sensor(text_sensor::TextSensor *s, uint8_t number, const char *object_id,
                                      const char *name, const char *unit, const char *device_class,
                                      uint8_t state_class, int8_t accuracy, uint8_t flags) {
  size_t index = this->entities_.size();
  this->add_entity_(3, s, number, object_id, name, unit, device_class, state_class, accuracy, flags);
  // TextSensor fires on every publish; only a changed value is worth a frame.
  s->add_on_state_callback([this, index](const std::string &value) {
    uint32_t hash = 2166136261u;  // FNV-1a
    for (char c : value) hash = (hash ^ static_cast<uint8_t>(c)) * 16777619u;
    Entity &entity = this->entities_[index];
    if (hash != entity.last) entity.dirty = true;
    entity.last = hash;
  });
}

void ServerBuddyNode::build_schema_() {
  sb_schema_t schema{};
  schema.node_name = text(this->node_name_);
  schema.model = text(this->model_);
  schema.fw_version = text(this->fw_version_);
  schema.n = 0;
  static const uint8_t VALUE_TYPES[] = {0, SB_V_F32, SB_V_BOOL, SB_V_STR};
  for (const auto &entity : this->entities_) {
    sb_entity_t &e = schema.e[schema.n++];
    e.entity = entity.number;
    e.platform = entity.platform;
    e.value_type = VALUE_TYPES[entity.platform];
    e.state_class = entity.state_class;
    e.accuracy = entity.accuracy;
    e.flags = entity.flags;
    e.object_id = text(entity.object_id);
    e.name = text(entity.name);
    e.unit = text(entity.unit);
    e.device_class = text(entity.device_class);
    e.extra = text("");
  }
  sb_entity_t &boot = schema.e[schema.n++];
  boot.entity = this->boot_number_;
  boot.platform = 4;  // event
  boot.value_type = SB_V_ENUM;
  boot.accuracy = -1;
  boot.object_id = text("boot");
  boot.name = text("Boot");
  boot.unit = boot.device_class = text("");
  boot.extra = text("boot");
  if (sb_encode_schema(&schema, this->schema_blob_, sizeof this->schema_blob_, &this->schema_len_) != SB_OK ||
      !sb_schema_hash(this->schema_blob_, this->schema_len_, &this->schema_hash_)) {
    ESP_LOGE(TAG, "Cannot encode node schema");
    this->mark_failed();
    return;
  }
  this->describe_count_ = (this->schema_len_ + SB_MAX_DESCRIBE_DATA - 1) / SB_MAX_DESCRIBE_DATA;
  ESP_LOGI(TAG, "Node schema: %u bytes, %u chunks", static_cast<unsigned>(this->schema_len_),
           this->describe_count_);
}

void ServerBuddyNode::setup() {
  if (this->radio_ == nullptr || this->entities_.empty() || this->entities_.size() >= SB_MAX_ENTITIES ||
      !sb_key_id(this->node_key_.data(), this->key_id_) ||
      esp_wifi_get_mac(WIFI_IF_STA, this->node_mac_) != ESP_OK ||
      esp_now_set_pmk(SB_PMK) != ESP_OK || nvs_flash_init() != ESP_OK || !this->increment_boot_()) {
    ESP_LOGE(TAG, "Radio, crypto or boot-counter setup failed");
    this->mark_failed();
    return;
  }
  this->radio_->register_receive_handler(this);
  this->build_schema_();
  if (this->is_failed()) return;
  this->paired_ = this->load_session_();
  if (!this->install_peer_(this->paired_)) {
    ESP_LOGE(TAG, "Cannot add hub ESP-NOW peer");
    this->mark_failed();
    return;
  }
  this->origin_boot_ = this->boot_;
  this->next_report_ms_ = millis();
  ESP_LOGI(TAG, "Channel=%u, %s; %u entities, full report every %us", this->radio_->get_wifi_channel(),
           this->paired_ ? "restored encrypted session" : "waiting for targeted pairing",
           static_cast<unsigned>(this->entities_.size()), static_cast<unsigned>(this->report_ms_ / 1000));
}

void ServerBuddyNode::dump_config() {
  ESP_LOGCONFIG(TAG, "Server Buddy ESP-NOW node (protocol v%u)", SB_VERSION);
  ESP_LOGCONFIG(TAG, "  Hub MAC: %02x:%02x:%02x:%02x:%02x:%02x", this->hub_mac_[0], this->hub_mac_[1],
                this->hub_mac_[2], this->hub_mac_[3], this->hub_mac_[4], this->hub_mac_[5]);
  ESP_LOGCONFIG(TAG, "  Channel: %u, report interval: %us", this->radio_->get_wifi_channel(),
                static_cast<unsigned>(this->report_ms_ / 1000));
  static const char *const KINDS[] = {"", "sensor", "binary_sensor", "text_sensor"};
  for (const auto &entity : this->entities_)
    ESP_LOGCONFIG(TAG, "  #%u %s '%s' (%s)", entity.number, KINDS[entity.platform], entity.name, entity.object_id);
}

void ServerBuddyNode::send_pair_request_() {
  sb_frame_t request{};
  request.type = SB_MSG_PAIR_REQUEST;
  request.boot = this->boot_;
  request.seq = ++this->seq_;
  memcpy(request.u.pair_req.key_id, this->key_id_, SB_KEY_ID_LEN);
  memcpy(request.u.pair_req.mac, this->node_mac_, 6);
  esp_fill_random(this->nonce_, sizeof this->nonce_);
  memcpy(request.u.pair_req.nonce, this->nonce_, sizeof this->nonce_);
  uint8_t frame[SB_MAX_FRAME];
  size_t len = 0;
  if (sb_encode(&request, frame, sizeof frame, &len) != SB_OK ||
      !sb_request_tag(this->node_key_.data(), frame, len - SB_TAG_LEN, frame + len - SB_TAG_LEN))
    return;
  this->radio_->send(BROADCAST, frame, len, [](esp_err_t) {});
  this->next_pair_ms_ = millis() + 500;
}

void ServerBuddyNode::handle_pair_response_(const uint8_t *data, size_t len, const sb_frame_t &f) {
  if (this->paired_ || this->pair_confirming_ || f.u.pair_resp.status != SB_PAIR_ACCEPTED ||
      !f.u.pair_resp.pepoch || memcmp(f.u.pair_resp.mac, this->hub_mac_.data(), 6) != 0)
    return;
  uint8_t expected[SB_TAG_LEN];
  if (!sb_response_tag(this->node_key_.data(), this->nonce_, data, len - SB_TAG_LEN, expected) ||
      !sb_tag_equal(expected, f.u.pair_resp.tag, SB_TAG_LEN))
    return;
  this->epoch_ = f.u.pair_resp.pepoch;
  if (!sb_session_keys(this->node_key_.data(), this->nonce_, f.u.pair_resp.nonce, this->node_mac_,
                       this->hub_mac_.data(), this->epoch_, this->lmk_, this->k_mic_) ||
      !this->install_peer_(true)) {
    this->forget_pending_pair_();
    return;
  }
  this->pair_confirming_ = true;
  this->confirm_after_ms_ = millis() + 250;  // hub installs LMK after PAIR_RESPONSE send-done
  ESP_LOGI(TAG, "Verified hub pairing response; confirming encrypted session");
}

void ServerBuddyNode::forget_pending_pair_() {
  this->pending_ = Pending::NONE;
  this->pair_confirming_ = false;
  this->epoch_ = 0;
  memset(this->lmk_, 0, sizeof this->lmk_);
  memset(this->k_mic_, 0, sizeof this->k_mic_);
  this->install_peer_(false);
  this->next_pair_ms_ = millis() + 500;
}

bool ServerBuddyNode::begin_frame_(sb_frame_t &f, Pending kind) {
  f.epoch = this->epoch_;
  f.boot = this->boot_;
  f.seq = ++this->seq_;
  f.flags |= SB_FLAG_ACK_REQ;
  size_t len = 0;
  if (sb_encode(&f, this->frame_, sizeof this->frame_, &len) != SB_OK ||
      !sb_mic_seal(this->k_mic_, SB_DIR_NODE_TO_HUB, this->frame_, len))
    return false;
  this->pending_ = kind;
  this->pending_seq_ = f.seq;
  this->pending_boot_ = f.boot;
  this->frame_len_ = len;
  this->attempts_ = 0;
  this->retransmit_();
  return true;
}

void ServerBuddyNode::retransmit_() {
  this->attempts_++;
  this->last_send_ms_ = millis();
  esp_err_t err = this->radio_->send(this->hub_mac_.data(), this->frame_, this->frame_len_,
                                      [](esp_err_t) {});
  if (err != ESP_OK) ESP_LOGW(TAG, "ESP-NOW send queued failed: %s", esp_err_to_name(err));
}

void ServerBuddyNode::send_hello_() {
  sb_frame_t hello{};
  hello.type = SB_MSG_HELLO;
  hello.u.hello.schema_hash = this->schema_hash_;
  hello.u.hello.interval = this->report_ms_ / 1000;  // hub availability timeout = 3x
  hello.u.hello.reason = 1;  // power on
  if (!this->begin_frame_(hello, Pending::HELLO)) ESP_LOGE(TAG, "HELLO encode failed");
}

void ServerBuddyNode::send_describe_() {
  const size_t offset = static_cast<size_t>(this->describe_index_) * SB_MAX_DESCRIBE_DATA;
  const size_t chunk = std::min(this->schema_len_ - offset, static_cast<size_t>(SB_MAX_DESCRIBE_DATA));
  sb_frame_t describe{};
  describe.type = SB_MSG_DESCRIBE;
  describe.u.describe.xfer = 1;
  describe.u.describe.index = this->describe_index_;
  describe.u.describe.count = this->describe_count_;
  describe.u.describe.total = this->schema_len_;
  describe.u.describe.hash = this->schema_hash_;
  describe.u.describe.data = this->schema_blob_ + offset;
  describe.u.describe.data_len = chunk;
  if (!this->begin_frame_(describe, Pending::DESCRIBE)) ESP_LOGE(TAG, "DESCRIBE encode failed");
}

void ServerBuddyNode::send_boot_event_() {
  sb_frame_t event{};
  event.type = SB_MSG_EVENT;
  event.u.event.entity = this->boot_number_;
  event.u.event.etype = 0;
  event.u.event.oboot = this->origin_boot_;
  event.u.event.evno = 1;
  event.u.event.value.type = SB_V_NONE;
  if (!this->begin_frame_(event, Pending::BOOT_EVENT)) ESP_LOGE(TAG, "boot EVENT encode failed");
}

// Current value of an entity; NONE when unknown. Returns the STATE entry size
// (entity byte + VALUE). `text` backs STR values until the frame is encoded.
size_t ServerBuddyNode::value_(const Entity &entity, sb_value_t &value, char *text, size_t cap) const {
  value = {};
  value.type = SB_V_NONE;
  if (entity.platform == 1) {
    auto *s = static_cast<sensor::Sensor *>(entity.source);
    if (s->has_state() && std::isfinite(s->state)) {
      value.type = SB_V_F32;
      value.f = s->state;
      return 1 + 5;
    }
  } else if (entity.platform == 2) {
    auto *s = static_cast<binary_sensor::BinarySensor *>(entity.source);
    if (s->has_state()) {
      value.type = SB_V_BOOL;
      value.b = s->state;
      return 1 + 2;
    }
  } else if (entity.platform == 3) {
    auto *s = static_cast<text_sensor::TextSensor *>(entity.source);
    if (s->has_state()) {
      // Protocol strings are <= 64 bytes of strict UTF-8 without NUL: trim to
      // a character boundary; anything still invalid is reported as unknown.
      size_t len = std::min(s->state.size(), std::min(cap - 1, static_cast<size_t>(SB_MAX_STR)));
      memcpy(text, s->state.data(), len);
      while (len > 0 && !sb_utf8_valid(reinterpret_cast<const uint8_t *>(text), len) &&
             (static_cast<uint8_t>(text[len - 1]) & 0x80))
        len--;
      if (sb_utf8_valid(reinterpret_cast<const uint8_t *>(text), len)) {
        value.type = SB_V_STR;
        value.s = {reinterpret_cast<const uint8_t *>(text), static_cast<uint8_t>(len)};
        return 1 + 2 + len;
      }
    }
  }
  return 1 + 1;
}

// Send the next frame's worth of changed entities. Returns false if none are due.
bool ServerBuddyNode::send_state_batch_() {
  static char texts[SB_MAX_STATE_ENTRIES][SB_MAX_STR + 1];
  sb_frame_t state{};
  state.type = SB_MSG_STATE;
  size_t payload = 1;  // entry count
  this->batch_.clear();
  for (size_t i = 0; i < this->entities_.size() && state.u.state.n < SB_MAX_STATE_ENTRIES; i++) {
    Entity &entity = this->entities_[i];
    if (!entity.dirty) continue;
    uint8_t slot = state.u.state.n;
    size_t size = this->value_(entity, state.u.state.e[slot].value, texts[slot], sizeof texts[slot]);
    if (payload + size > SB_MAX_PAYLOAD) continue;  // goes in the next frame; keep packing others
    state.u.state.e[slot].entity = entity.number;
    state.u.state.n++;
    payload += size;
    this->batch_.push_back(i);
  }
  if (this->batch_.empty()) return false;
  if (this->batch_.size() == this->entities_.size()) state.flags = SB_FLAG_FULL_STATE;
  // Clear now: a change while the frame is in flight re-marks the entity.
  for (uint8_t index : this->batch_) this->entities_[index].dirty = false;
  if (!this->begin_frame_(state, Pending::STATE)) {
    ESP_LOGE(TAG, "STATE encode failed");
    for (uint8_t index : this->batch_) this->entities_[index].dirty = true;
    this->backoff_ = true;
    this->retry_after_ms_ = millis() + STATE_RETRY_MS;
    return false;
  }
  return true;
}

void ServerBuddyNode::handle_ack_(const uint8_t *data, size_t len, const sb_frame_t &f) {
  if (this->pending_ == Pending::NONE || f.epoch != this->epoch_ ||
      !sb_mic_verify(this->k_mic_, SB_DIR_HUB_TO_NODE, data, len) ||
      f.u.ack.aboot != this->pending_boot_ || f.u.ack.aseq != this->pending_seq_)
    return;
  if (f.u.ack.status == SB_ACK_NEW_BOOT) {
    // Hub restarted: the frame was not processed. Re-announce and resend it all.
    this->pending_ = Pending::NONE;
    if (!this->increment_boot_()) this->mark_failed();
    this->hello_done_ = false;
    this->need_describe_ = false;
    this->describe_index_ = 0;
    this->next_hello_ms_ = millis();  // a stale deadline could otherwise block HELLO
    for (auto &entity : this->entities_) entity.dirty = true;
    return;
  }
  Pending kind = this->pending_;
  this->pending_ = Pending::NONE;
  if (f.u.ack.status == SB_ACK_BUSY || f.u.ack.status == SB_ACK_MALFORMED) {
    ESP_LOGW(TAG, "hub rejected frame type=%u status=%u", static_cast<unsigned>(kind), f.u.ack.status);
    if (kind == Pending::HELLO) this->next_hello_ms_ = millis() + 1000;
    if (kind == Pending::DESCRIBE) this->last_send_ms_ = millis() + 1000;
    // BUSY is transient: resend. MALFORMED would repeat forever: drop it.
    if (kind == Pending::STATE && f.u.ack.status == SB_ACK_BUSY) {
      for (uint8_t index : this->batch_) this->entities_[index].dirty = true;
      this->backoff_ = true;
      this->retry_after_ms_ = millis() + STATE_RETRY_MS;
    }
    return;
  }
  if (kind == Pending::HELLO) {
    if (this->pair_confirming_) {
      // Persist only after the authenticated hub ACK confirms it committed.
      if (!this->store_session_()) {
        ESP_LOGE(TAG, "cannot persist paired session");
        this->mark_failed();
        return;
      }
      this->pair_confirming_ = false;
      this->paired_ = true;
      ESP_LOGI(TAG, "encrypted pairing confirmed and persisted");
    }
    this->hello_done_ = true;
    this->need_describe_ = f.u.ack.status == SB_ACK_NEED_DESCRIBE;
    this->describe_index_ = 0;
  } else if (kind == Pending::DESCRIBE) {
    if (++this->describe_index_ >= this->describe_count_) this->need_describe_ = false;
  } else if (kind == Pending::BOOT_EVENT) {
    // NEED_DESCRIBE means the hub could not deliver the event yet. Resend
    // the original (origin_boot, event_no) after installing the schema.
    if (f.u.ack.status != SB_ACK_NEED_DESCRIBE) this->boot_event_acked_ = true;
  } else if (kind == Pending::STATE) {
    ESP_LOGD(TAG, "state ACKed (%u entities)", static_cast<unsigned>(this->batch_.size()));
  }
  if (f.u.ack.status == SB_ACK_NEED_DESCRIBE && kind != Pending::HELLO) {
    // The hub lost our schema: re-announce, then resend everything.
    this->hello_done_ = false;
    this->need_describe_ = false;
    this->next_hello_ms_ = millis();
    for (auto &entity : this->entities_) entity.dirty = true;
  }
}

bool ServerBuddyNode::on_receive(const espnow::ESPNowRecvInfo &info, const uint8_t *data, ReceiveSize size) {
  if (memcmp(info.src_addr, this->hub_mac_.data(), 6) != 0 || size > SB_MAX_FRAME) return false;
  // An enrolled frame must authenticate BEFORE decoding; PAIR_RESPONSE carries a
  // separate node-key tag instead of a MIC.
  if (size < SB_HEADER_LEN || data[3] != SB_MSG_PAIR_RESPONSE) {
    if (!sb_mic_verify(this->k_mic_, SB_DIR_HUB_TO_NODE, data, size)) return false;
  }
  sb_frame_t f{};
  if (sb_decode(data, size, &f) != SB_OK) return false;
  if (f.type == SB_MSG_PAIR_RESPONSE) this->handle_pair_response_(data, size, f);
  else if (f.type == SB_MSG_ACK) this->handle_ack_(data, size, f);
  return true;
}

void ServerBuddyNode::failed_frame_() {
  Pending kind = this->pending_;
  this->pending_ = Pending::NONE;
  if (kind == Pending::HELLO) {
    if (this->pair_confirming_) this->forget_pending_pair_();
    else this->next_hello_ms_ = millis() + std::min(this->report_ms_, HELLO_RETRY_MS);
  } else if (kind == Pending::STATE) {
    // Hub unreachable: keep the values and retry later without flooding.
    for (uint8_t index : this->batch_) this->entities_[index].dirty = true;
    this->backoff_ = true;
    this->retry_after_ms_ = millis() + STATE_RETRY_MS;
  } else if (kind == Pending::DESCRIBE) {
    this->last_send_ms_ = millis() + 1000;
  } else if (kind == Pending::BOOT_EVENT) {
    this->backoff_ = true;
    this->retry_after_ms_ = millis() + STATE_RETRY_MS;
  }
}

void ServerBuddyNode::loop() {
  if (this->is_failed()) return;
  const uint32_t now = millis();
  if (this->pending_ != Pending::NONE) {
    if (now - this->last_send_ms_ >= ACK_TIMEOUT_MS) {
      if (this->attempts_ < MAX_ATTEMPTS) this->retransmit_();
      else this->failed_frame_();
    }
    return;
  }
  if (this->pair_confirming_) {
    if (static_cast<int32_t>(now - this->confirm_after_ms_) >= 0) this->send_hello_();
    return;
  }
  if (!this->paired_) {
    if (static_cast<int32_t>(now - this->next_pair_ms_) >= 0) this->send_pair_request_();
    return;
  }
  if (!this->hello_done_) {
    if (static_cast<int32_t>(now - this->next_hello_ms_) >= 0) this->send_hello_();
    return;
  }
  if (this->need_describe_) {
    if (static_cast<int32_t>(now - this->last_send_ms_) >= 0) this->send_describe_();
    return;
  }
  if (this->backoff_) {
    if (static_cast<int32_t>(now - this->retry_after_ms_) < 0) return;
    this->backoff_ = false;
  }
  if (!this->boot_event_acked_) {
    this->send_boot_event_();
    return;
  }
  if (static_cast<int32_t>(now - this->next_report_ms_) >= 0) {
    // Periodic full report: sensors are sampled here; it also refreshes the
    // hub's availability timer (3 x report interval).
    for (auto &entity : this->entities_) entity.dirty = true;
    this->next_report_ms_ = now + this->report_ms_;
  }
  this->send_state_batch_();  // changed binary/text sensors go out immediately
}

}  // namespace esphome::server_buddy
