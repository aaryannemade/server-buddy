# Server Buddy

## Info

An ESP32-P4 Ethernet/PoE board that serves multiple functions.

The main functions are:

- An ESP-NOW router to Home Assistant that works like an MQTT hub.
- Connection to an XIA logger hat for server cabinet temperature, humidity, and
  brightness.
- Connection to an LED matrix display to show server statistics.
- A serial TTY port over USB for direct Raspberry Pi troubleshooting.

See the [implementation plan](docs/IMPLEMENTATION_PLAN.md) for the proposed
architecture, development phases, test gates, and recovery process.
