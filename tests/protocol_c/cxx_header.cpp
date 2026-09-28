// Compile-only check: headers must be valid ISO C++ for ESPHome components.
#include "sb_crypto.h"
#include "sb_protocol.h"

int main()
{
    sb_frame_t f{};
    f.u.event.value.type = SB_V_F32;
    f.u.event.value.f = 1.0f;
    return sb_has_mic(f.type) ? 0 : 1;
}
