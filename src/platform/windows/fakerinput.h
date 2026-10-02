/**
 * @file src/platform/windows/fakerinput.h
 * @brief Route mouse input to the FakerInput virtual HID driver (POC).
 *
 * FakerInput (Ryochan7) is a user-mode virtual HID driver. Games that ignore
 * SendInput (e.g. Vanguard-protected titles) accept input coming from this
 * virtual HID device. This module locates the driver's HID collections and
 * submits relative-mouse reports to it.
 */
#pragma once

// standard includes
#include <cstdint>

namespace fakerinput {
  /**
   * @brief Locate the FakerInput HID collections and perform the API handshake.
   * @return True if the device was found and is usable.
   */
  bool init();

  /**
   * @brief Whether the FakerInput device is currently open and usable.
   */
  bool connected();

  /**
   * @brief Send a relative mouse movement (uses the tracked button state).
   */
  void move(short dx, short dy);

  /**
   * @brief Update a mouse button and report the new button state.
   * @param button Moonlight button id (BUTTON_LEFT..BUTTON_X2).
   * @param release True on release, false on press.
   */
  void button(int button, bool release);

  /**
   * @brief Send wheel/h-wheel ticks (1 tick == WHEEL_DELTA/120).
   */
  void scroll(int wheel_ticks, int hwheel_ticks);

  /**
   * @brief Close the device handles.
   */
  void shutdown();
}  // namespace fakerinput
