/**
 * @file src/platform/windows/fakerinput.cpp
 * @brief Route mouse input to the FakerInput virtual HID driver (POC).
 */
#include "fakerinput.h"

// platform includes
#include <windows.h>
#include <hidsdi.h>
#include <setupapi.h>

// standard includes
#include <cstdint>
#include <cstring>
#include <mutex>

// local includes
#include "src/logging.h"

namespace fakerinput {
  namespace {
    constexpr USHORT FAKERINPUT_VID = 0xFE0F;
    constexpr USHORT FAKERINPUT_PID = 0x00FF;

    constexpr USHORT FAKERINPUT_USAGE_PAGE_CONTROL = 0xFF00;
    constexpr USHORT FAKERINPUT_USAGE_CONTROL = 0x0001;
    constexpr USHORT FAKERINPUT_USAGE_PAGE_ENDPOINT = 0xFF00;
    constexpr USHORT FAKERINPUT_USAGE_ENDPOINT = 0x0002;

    constexpr std::uint8_t REPORTID_RELATIVE_MOUSE = 0x03;
    constexpr std::uint8_t REPORTID_CONTROL = 0x40;
    constexpr std::uint8_t REPORTID_CHECK_API_VERSION = 0x41;
    constexpr std::uint32_t FAKERINPUT_API_VERSION = 0x01;
    constexpr std::size_t CONTROL_REPORT_SIZE = 0x41;  // 65 bytes, matches FakerInputDll

    HANDLE control_handle = INVALID_HANDLE_VALUE;
    HANDLE endpoint_handle = INVALID_HANDLE_VALUE;
    std::uint8_t button_mask = 0;
    std::mutex report_mutex;

    /**
     * @brief Enumerate HID collections and open the one matching the given usage.
     */
    HANDLE find_device(USHORT usage_page, USHORT usage) {
      GUID hid_guid;
      HidD_GetHidGuid(&hid_guid);

      HDEVINFO dev_info = SetupDiGetClassDevs(&hid_guid, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
      if (dev_info == INVALID_HANDLE_VALUE) {
        return INVALID_HANDLE_VALUE;
      }

      SP_DEVICE_INTERFACE_DATA iface {};
      iface.cbSize = sizeof(iface);

      for (DWORD i = 0; SetupDiEnumDeviceInterfaces(dev_info, nullptr, &hid_guid, i, &iface); ++i) {
        DWORD required = 0;
        SetupDiGetDeviceInterfaceDetail(dev_info, &iface, nullptr, 0, &required, nullptr);
        if (required == 0) {
          continue;
        }

        auto *detail = static_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA>(malloc(required));
        if (!detail) {
          continue;
        }
        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

        if (!SetupDiGetDeviceInterfaceDetail(dev_info, &iface, detail, required, &required, nullptr)) {
          free(detail);
          continue;
        }

        HANDLE file = CreateFile(detail->DevicePath, GENERIC_READ | GENERIC_WRITE,
          FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        free(detail);

        if (file == INVALID_HANDLE_VALUE) {
          continue;
        }

        HIDD_ATTRIBUTES attributes {};
        if (!HidD_GetAttributes(file, &attributes) ||
            attributes.VendorID != FAKERINPUT_VID || attributes.ProductID != FAKERINPUT_PID) {
          CloseHandle(file);
          continue;
        }

        PHIDP_PREPARSED_DATA preparsed = nullptr;
        if (!HidD_GetPreparsedData(file, &preparsed)) {
          CloseHandle(file);
          continue;
        }

        HIDP_CAPS caps {};
        bool match = false;
        if (HidP_GetCaps(preparsed, &caps)) {
          match = (caps.UsagePage == usage_page && caps.Usage == usage);
        }
        HidD_FreePreparsedData(preparsed);

        if (match) {
          SetupDiDestroyDeviceInfoList(dev_info);
          return file;
        }

        CloseHandle(file);
      }

      SetupDiDestroyDeviceInfoList(dev_info);
      return INVALID_HANDLE_VALUE;
    }

    /**
     * @brief Wrap an inner HID report in the FakerInput control envelope and send it.
     */
    bool send_control_report(const std::uint8_t *report, std::size_t report_len) {
      if (report_len > CONTROL_REPORT_SIZE - 2) {
        return false;
      }

      std::uint8_t buffer[CONTROL_REPORT_SIZE];
      std::memset(buffer, 0, sizeof(buffer));
      buffer[0] = REPORTID_CONTROL;
      buffer[1] = static_cast<std::uint8_t>(report_len);
      std::memcpy(buffer + 2, report, report_len);

      DWORD written = 0;
      return WriteFile(control_handle, buffer, sizeof(buffer), &written, nullptr) != 0;
    }
  }  // namespace

  bool init() {
    control_handle = find_device(FAKERINPUT_USAGE_PAGE_CONTROL, FAKERINPUT_USAGE_CONTROL);
    if (control_handle == INVALID_HANDLE_VALUE) {
      BOOST_LOG(warning) << "FakerInput: control device not found";
      return false;
    }

    endpoint_handle = find_device(FAKERINPUT_USAGE_PAGE_ENDPOINT, FAKERINPUT_USAGE_ENDPOINT);
    if (endpoint_handle == INVALID_HANDLE_VALUE) {
      BOOST_LOG(warning) << "FakerInput: method endpoint not found";
      CloseHandle(control_handle);
      control_handle = INVALID_HANDLE_VALUE;
      return false;
    }

    // The driver casts the report buffer to FakerInputAPIVersionReport
    // { BYTE ReportID; UINT32 ApiVersion; } with natural alignment, so the API
    // version lives at offset 4 (3 bytes of padding after the report id byte).
    struct api_version_report {
      std::uint8_t report_id;
      std::uint32_t api_version;
    };
    static_assert(sizeof(api_version_report) == 8, "unexpected struct padding");

    alignas(api_version_report) std::uint8_t version_report[CONTROL_REPORT_SIZE] {};
    auto *report = reinterpret_cast<api_version_report *>(version_report);
    report->report_id = REPORTID_CHECK_API_VERSION;
    report->api_version = FAKERINPUT_API_VERSION;

    DWORD written = 0;
    if (!WriteFile(endpoint_handle, version_report, sizeof(version_report), &written, nullptr)) {
      const DWORD error = GetLastError();
      BOOST_LOG(warning) << "FakerInput: API version handshake failed: " << error;
      shutdown();
      return false;
    }

    BOOST_LOG(info) << "FakerInput: connected";
    return true;
  }

  bool connected() {
    return control_handle != INVALID_HANDLE_VALUE;
  }

  void move(short dx, short dy) {
    if (!connected()) {
      return;
    }

    std::lock_guard<std::mutex> lock(report_mutex);
    std::uint8_t report[8];
    report[0] = REPORTID_RELATIVE_MOUSE;
    report[1] = button_mask;
    report[2] = static_cast<std::uint8_t>(dx & 0xFF);
    report[3] = static_cast<std::uint8_t>((dx >> 8) & 0xFF);
    report[4] = static_cast<std::uint8_t>(dy & 0xFF);
    report[5] = static_cast<std::uint8_t>((dy >> 8) & 0xFF);
    report[6] = 0;
    report[7] = 0;
    send_control_report(report, sizeof(report));
  }

  void button(int button, bool release) {
    if (!connected()) {
      return;
    }

    std::uint8_t bit = 0;
    switch (button) {
      case 0x01: bit = 0x01; break;  // left
      case 0x02: bit = 0x04; break;  // middle
      case 0x03: bit = 0x02; break;  // right
      case 0x04: bit = 0x08; break;  // X1
      case 0x05: bit = 0x10; break;  // X2
      default: return;
    }

    std::lock_guard<std::mutex> lock(report_mutex);
    if (release) {
      button_mask = static_cast<std::uint8_t>(button_mask & ~bit);
    } else {
      button_mask = static_cast<std::uint8_t>(button_mask | bit);
    }

    std::uint8_t report[8] = { REPORTID_RELATIVE_MOUSE, button_mask, 0, 0, 0, 0, 0, 0 };
    send_control_report(report, sizeof(report));
  }

  void scroll(int wheel_ticks, int hwheel_ticks) {
    if (!connected()) {
      return;
    }

    std::lock_guard<std::mutex> lock(report_mutex);
    std::uint8_t report[8];
    report[0] = REPORTID_RELATIVE_MOUSE;
    report[1] = button_mask;
    report[2] = 0;
    report[3] = 0;
    report[4] = 0;
    report[5] = 0;
    report[6] = static_cast<std::uint8_t>(wheel_ticks & 0xFF);
    report[7] = static_cast<std::uint8_t>(hwheel_ticks & 0xFF);
    send_control_report(report, sizeof(report));
  }

  void shutdown() {
    if (control_handle != INVALID_HANDLE_VALUE) {
      CloseHandle(control_handle);
      control_handle = INVALID_HANDLE_VALUE;
    }
    if (endpoint_handle != INVALID_HANDLE_VALUE) {
      CloseHandle(endpoint_handle);
      endpoint_handle = INVALID_HANDLE_VALUE;
    }
  }
}  // namespace fakerinput
