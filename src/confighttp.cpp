/**
 * @file src/confighttp.cpp
 * @brief Definitions for the Web UI Config HTTP server.
 *
 * @todo Authentication, better handling of routes common to nvhttp, cleanup
 */
#define BOOST_BIND_GLOBAL_PLACEHOLDERS

// CM_Register_Notification and related types require Windows 8+ SDK headers.
#ifdef _WIN32
  #ifndef _WIN32_WINNT
    #define _WIN32_WINNT 0x0A00
  #endif
  #ifndef WINVER
    #define WINVER 0x0A00
  #endif
#endif

// standard includes
#include <algorithm>
#include <filesystem>
#include <format>
#include <fstream>
#include <map>
#include <regex>
#include <set>
#include <string_view>
#include <atomic>
#include <mutex>
#include <thread>

// lib includes
#include <boost/algorithm/string.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/filesystem.hpp>
#include <nlohmann/json.hpp>
#include <Simple-Web-Server/crypto.hpp>
#include <Simple-Web-Server/server_https.hpp>

#ifdef _WIN32
  #include "platform/windows/misc.h"

  #include <chrono>
  #include <vector>
  #include <Windows.h>
  #include <cfgmgr32.h>
  #include <setupapi.h>
#endif

// local includes
#include "config.h"
#include "confighttp.h"
#include "crypto.h"
#include "display_device.h"
#include "file_handler.h"
#include "globals.h"
#include "httpcommon.h"
#include "logging.h"
#include "network.h"
#include "nvhttp.h"
#include "platform/common.h"
#include "process.h"
#include "rtsp.h"
#include "utility.h"
#include "uuid.h"

using namespace std::literals;

namespace confighttp {
  namespace fs = std::filesystem;

  /**
   * @brief HTTPS server type used for Sunshine's configuration UI.
   */
  using https_server_t = SimpleWeb::Server<SimpleWeb::HTTPS>;

  /**
   * @brief Case-insensitive map used for HTTP headers and query parameters.
   */
  using args_t = SimpleWeb::CaseInsensitiveMultimap;
  /**
   * @brief Shared HTTPS response object passed to configuration handlers.
   */
  using resp_https_t = std::shared_ptr<SimpleWeb::ServerBase<SimpleWeb::HTTPS>::Response>;
  /**
   * @brief Shared HTTPS request object received by configuration handlers.
   */
  using req_https_t = std::shared_ptr<SimpleWeb::ServerBase<SimpleWeb::HTTPS>::Request>;
  /**
   * @brief Handler signature for configuration UI HTTPS routes.
   */
  using https_handler_t = std::function<void(resp_https_t, req_https_t)>;

  /**
   * @brief Client certificate operations accepted by the configuration API.
   */
  enum class op_e {
    ADD,  ///< Add client
    REMOVE  ///< Remove client
  };

  // CSRF token management
  /**
   * @brief CSRF token value and its expiration deadline.
   */
  struct csrf_token_t {
    std::string token;  ///< Random token value that must be echoed by the client.
    std::chrono::steady_clock::time_point expiration;  ///< Monotonic deadline after which the token is rejected.
  };

  std::map<std::string, csrf_token_t, std::less<>> csrf_tokens;  ///< CSRF tokens by client identifier. NOSONAR(cpp:S5421) - intentionally mutable global
  std::mutex csrf_tokens_mutex;  ///< Mutex protecting CSRF token storage. NOSONAR(cpp:S5421) - intentionally mutable global

  // CSRF token configuration
  /**
   * @brief Number of random bytes used when generating a CSRF token.
   */
  constexpr auto CSRF_TOKEN_SIZE = 32;  // 32 bytes = 256 bits
  /**
   * @brief Amount of time a generated CSRF token remains valid.
   */
  constexpr auto CSRF_TOKEN_LIFETIME = std::chrono::hours(1);  // Tokens valid for 1 hour

  /**
   * @brief Log the request details.
   * @param request The HTTP request object.
   */
  void print_req(const req_https_t &request) {
    BOOST_LOG(debug) << "METHOD :: "sv << request->method;
    BOOST_LOG(debug) << "DESTINATION :: "sv << request->path;

    for (auto &[name, val] : request->header) {
      BOOST_LOG(debug) << name << " -- " << (name == "Authorization" ? "CREDENTIALS REDACTED" : val);
    }

    BOOST_LOG(debug) << " [--] "sv;

    for (auto &[name, val] : request->parse_query_string()) {
      BOOST_LOG(debug) << name << " -- " << val;
    }

    BOOST_LOG(debug) << " [--] "sv;
  }

  /**
   * @brief Send a response.
   * @param response The HTTP response object.
   * @param output_tree The JSON tree to send.
   */
  void send_response(const resp_https_t &response, const nlohmann::json &output_tree) {
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "application/json");
    headers.emplace("X-Frame-Options", "DENY");
    headers.emplace("Content-Security-Policy", "frame-ancestors 'none';");
    response->write(output_tree.dump(), headers);
  }

  /**
   * @brief Send a 401 Unauthorized response.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   */
  void send_unauthorized(const resp_https_t &response, const req_https_t &request) {
    auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
    BOOST_LOG(info) << "Web UI: ["sv << address << "] -- not authorized"sv;

    constexpr auto code = SimpleWeb::StatusCode::client_error_unauthorized;

    nlohmann::json tree;
    tree["status_code"] = code;
    tree["status"] = false;
    tree["error"] = "Unauthorized";

    const SimpleWeb::CaseInsensitiveMultimap headers {
      {"Content-Type", "application/json"},
      {"WWW-Authenticate", R"(Basic realm="Sunshine Gamestream Host", charset="UTF-8")"},
      {"X-Frame-Options", "DENY"},
      {"Content-Security-Policy", "frame-ancestors 'none';"}
    };

    response->write(code, tree.dump(), headers);
  }

  /**
   * @brief Send a redirect response.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * @param path The path to redirect to.
   */
  void send_redirect(const resp_https_t &response, const req_https_t &request, const char *path) {
    auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
    BOOST_LOG(info) << "Web UI: ["sv << address << "] -- not authorized"sv;
    const SimpleWeb::CaseInsensitiveMultimap headers {
      {"Location", path},
      {"X-Frame-Options", "DENY"},
      {"Content-Security-Policy", "frame-ancestors 'none';"}
    };
    response->write(SimpleWeb::StatusCode::redirection_temporary_redirect, headers);
  }

  /**
   * @brief Authenticate the user.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * @return True if the user is authenticated, false otherwise.
   */
  bool authenticate(const resp_https_t &response, const req_https_t &request) {
    auto address = net::addr_to_normalized_string(request->remote_endpoint().address());

    if (const auto ip_type = net::from_address(address); ip_type > http::origin_web_ui_allowed) {
      BOOST_LOG(info) << "Web UI: ["sv << address << "] -- denied"sv;
      response->write(SimpleWeb::StatusCode::client_error_forbidden);
      return false;
    }

    // If credentials are shown, redirect the user to a /welcome page
    if (config::sunshine.username.empty()) {
      send_redirect(response, request, "/welcome");
      return false;
    }

    auto fg = util::fail_guard([&]() {
      send_unauthorized(response, request);
    });

    const auto auth = request->header.find("authorization");
    if (auth == request->header.end()) {
      return false;
    }

    const auto &rawAuth = auth->second;
    auto authData = SimpleWeb::Crypto::Base64::decode(rawAuth.substr("Basic "sv.length()));

    const auto index = static_cast<int>(authData.find(':'));
    if (index >= authData.size() - 1) {
      return false;
    }

    const auto username = authData.substr(0, index);
    const auto password = authData.substr(index + 1);

    if (const auto hash = util::hex(crypto::hash(password + config::sunshine.salt)).to_string(); !boost::iequals(username, config::sunshine.username) || hash != config::sunshine.password) {
      return false;
    }

    fg.disable();
    return true;
  }

  /**
   * @brief Send a 404 Not Found response.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * @param error_message The error message to include in the response.
   */
  void not_found(const resp_https_t &response, [[maybe_unused]] const req_https_t &request, const std::string &error_message) {
    constexpr auto code = SimpleWeb::StatusCode::client_error_not_found;

    nlohmann::json tree;
    tree["status_code"] = code;
    tree["error"] = error_message;

    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "application/json");
    headers.emplace("X-Frame-Options", "DENY");
    headers.emplace("Content-Security-Policy", "frame-ancestors 'none';");

    response->write(code, tree.dump(), headers);
  }

  /**
   * @brief Send a 400 Bad Request response.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * @param error_message The error message to include in the response.
   */
  void bad_request(const resp_https_t &response, [[maybe_unused]] const req_https_t &request, const std::string &error_message) {
    constexpr auto code = SimpleWeb::StatusCode::client_error_bad_request;

    nlohmann::json tree;
    tree["status_code"] = code;
    tree["status"] = false;
    tree["error"] = error_message;

    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "application/json");
    headers.emplace("X-Frame-Options", "DENY");
    headers.emplace("Content-Security-Policy", "frame-ancestors 'none';");

    response->write(code, tree.dump(), headers);
  }

  /**
   * @brief Validate the request content type and send a bad request when mismatched.
   */
  bool check_content_type(const resp_https_t &response, const req_https_t &request, const std::string_view &contentType) {
    const auto requestContentType = request->header.find("content-type");
    if (requestContentType == request->header.end()) {
      bad_request(response, request, "Content type not provided");
      return false;
    }
    // Extract the media type part before any parameters (e.g., charset)
    std::string actualContentType = requestContentType->second;
    if (const size_t semicolonPos = actualContentType.find(';'); semicolonPos != std::string::npos) {
      actualContentType = actualContentType.substr(0, semicolonPos);
    }

    // Trim whitespace and convert to lowercase for case-insensitive comparison
    boost::algorithm::trim(actualContentType);
    boost::algorithm::to_lower(actualContentType);

    std::string expectedContentType(contentType);
    boost::algorithm::to_lower(expectedContentType);

    if (actualContentType != expectedContentType) {
      bad_request(response, request, "Content type mismatch");
      return false;
    }
    return true;
  }

  /**
   * @brief Get a unique client identifier for CSRF token management.
   * @param request The HTTP request object.
   * @return A unique identifier based on username or IP address.
   */
  std::string get_client_id(const req_https_t &request) {
    // Try to use the authenticated username as client ID
    if (const auto auth = request->header.find("authorization"); !config::sunshine.username.empty() && auth != request->header.end()) {
      if (const auto &rawAuth = auth->second; rawAuth.rfind("Basic "sv, 0) == 0) {
        auto authData = SimpleWeb::Crypto::Base64::decode(rawAuth.substr("Basic "sv.length()));
        if (const auto index = static_cast<int>(authData.find(':')); index < authData.size() - 1) {
          return authData.substr(0, index);  // Return username
        }
      }
    }

    // Fall back to IP address if no username
    return net::addr_to_normalized_string(request->remote_endpoint().address());
  }

  /**
   * @brief Generate a new CSRF token for a client.
   * @param client_id A unique identifier for the client (e.g., session ID or username).
   * @return The generated CSRF token.
   */
  std::string generate_csrf_token(const std::string &client_id) {
    // Generate a cryptographically secure random token
    std::string token = crypto::rand_alphabet(CSRF_TOKEN_SIZE);

    std::scoped_lock lock(csrf_tokens_mutex);

    // Clean up expired tokens first
    const auto now = std::chrono::steady_clock::now();
    std::erase_if(csrf_tokens, [&now](const auto &entry) {
      return entry.second.expiration < now;
    });

    // Store the token with expiration
    csrf_tokens[client_id] = csrf_token_t {
      token,
      now + CSRF_TOKEN_LIFETIME
    };

    return token;
  }

  /**
   * @brief Validate a stored CSRF token for a client against a provided token string.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * @param client_id A unique identifier for the client.
   * @param provided_token The token string to validate.
   * @return True if the token is valid, false otherwise.
   */
  bool validate_stored_csrf_token(const resp_https_t &response, const req_https_t &request, const std::string_view client_id, const std::string_view provided_token) {
    std::scoped_lock lock(csrf_tokens_mutex);
    const auto token_it = csrf_tokens.find(client_id);

    if (token_it == csrf_tokens.end()) {
      auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
      BOOST_LOG(error) << "Web UI: ["sv << address << "] -- CSRF token validation failed: no token found for client"sv;
      bad_request(response, request, "Invalid CSRF token");
      return false;
    }

    if (const auto now = std::chrono::steady_clock::now(); token_it->second.expiration < now) {
      csrf_tokens.erase(token_it);
      auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
      BOOST_LOG(error) << "Web UI: ["sv << address << "] -- CSRF token validation failed: token expired"sv;
      bad_request(response, request, "CSRF token expired");
      return false;
    }

    if (token_it->second.token != provided_token) {
      auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
      BOOST_LOG(error) << "Web UI: ["sv << address << "] -- CSRF token validation failed: token mismatch"sv;
      bad_request(response, request, "Invalid CSRF token");
      return false;
    }

    return true;
  }

  /**
   * @brief Validate CSRF token.
   */
  bool validate_csrf_token(const resp_https_t &response, const req_https_t &request, const std::string &client_id) {
    // Helper function to check if a URL starts with any allowed origin
    auto is_allowed_origin = [](const std::string_view url) {
      return std::ranges::any_of(config::sunshine.csrf_allowed_origins, [&url](const std::string &allowed_origin) {
        // Ensure exact prefix match (with ":" or "/" after to prevent malicious.com matching allowed.com)
        if (url.rfind(allowed_origin, 0) != 0) {  // rfind with pos=0 checks if the url starts with allowed_origin
          return false;
        }
        // Check that it's followed by ":" (port) or "/" (path) or is an exact match
        const size_t len = allowed_origin.length();
        return url.length() == len || url[len] == ':' || url[len] == '/';
      });
    };

    // Check if the request is from the same origin (Origin or Referer header matches configured allowed origins)
    const auto origin_it = request->header.find("Origin");
    if (origin_it != request->header.end() && is_allowed_origin(origin_it->second)) {
      // Same origin request - allow without CSRF token
      return true;
    }

    // If we have a Referer header, check if it's same-origin
    const auto referer_it = request->header.find("Referer");
    if (referer_it != request->header.end() && is_allowed_origin(referer_it->second)) {
      // Same origin request - allow without CSRF token
      return true;
    }

    // If neither Origin nor Referer is present, this cannot be a browser-initiated CSRF attack.
    // Non-browser clients (e.g. curl, scripts) never send these headers, and a malicious web page
    // cannot cause a non-browser client to make requests on a user's behalf.
    if (origin_it == request->header.end() && referer_it == request->header.end()) {
      return true;
    }

    // A browser-like request arrived with an Origin/Referer that doesn't match an allowed origin.
    // Require a CSRF token.
    const std::string_view blocked_origin = (origin_it != request->header.end()) ? origin_it->second : referer_it->second;
    // Extract token from X-CSRF-Token header
    const auto header_it = request->header.find("X-CSRF-Token");
    if (header_it == request->header.end()) {
      // Also check query parameters as fallback
      auto query_params = request->parse_query_string();
      const auto query_it = query_params.find("csrf_token");
      if (query_it == query_params.end()) {
        auto address = net::addr_to_normalized_string(request->remote_endpoint().address());
        BOOST_LOG(error) << "Web UI: ["sv << address << "] -- CSRF protection blocked request from origin: "sv << blocked_origin;
        BOOST_LOG(error) << "Web UI: To allow this origin, add it to the 'csrf_allowed_origins' option in your Sunshine configuration"sv;
        bad_request(response, request, "Missing CSRF token");
        return false;
      }

      return validate_stored_csrf_token(response, request, client_id, query_it->second);
    }

    // Validate token from header
    return validate_stored_csrf_token(response, request, client_id, header_it->second);
  }

  /**
   * @brief Validates the application index and sends an error response if invalid.
   */
  bool check_app_index(const resp_https_t &response, const req_https_t &request, int index) {
    std::string file = file_handler::read_file(config::stream.file_apps.c_str());
    nlohmann::json file_tree = nlohmann::json::parse(file);
    if (const auto &apps = file_tree["apps"]; index < 0 || index >= static_cast<int>(apps.size())) {
      std::string error;
      if (const int max_index = static_cast<int>(apps.size()) - 1; max_index < 0) {
        error = "No applications found";
      } else {
        error = std::format("'index' {} out of range, max index is {}", index, max_index);
      }
      bad_request(response, request, error);
      return false;
    }
    return true;
  }

  /**
   * @brief Get an HTML page.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * @param html_file The HTML file to serve (relative to WEB_DIR).
   * @param require_auth Whether to require authentication (default: true).
   * @param redirect_if_username If true, redirect to "/" when the username is set (for welcome page).
   */
  void getPage(const resp_https_t &response, const req_https_t &request, const char *html_file, const bool require_auth, const bool redirect_if_username) {
    // Special handling for welcome page: redirect if the username is already set
    if (redirect_if_username && !config::sunshine.username.empty()) {
      send_redirect(response, request, "/");
      return;
    }

    if (require_auth && !authenticate(response, request)) {
      return;
    }

    print_req(request);

    const std::string content = file_handler::read_file((std::string(WEB_DIR) + html_file).c_str());
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/html; charset=utf-8");

    // prevent click jacking
    headers.emplace("X-Frame-Options", "DENY");
    headers.emplace("Content-Security-Policy", "frame-ancestors 'none';");

    response->write(content, headers);
  }

  /**
   * @brief Get the favicon image.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * @todo combine function with getSunshineLogoImage and possibly getNodeModules
   * @todo use mime_types map
   */
  void getFaviconImage(const resp_https_t &response, const req_https_t &request) {
    print_req(request);

    std::ifstream in(WEB_DIR "images/sunshine.ico", std::ios::binary);
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "image/x-icon");
    headers.emplace("X-Frame-Options", "DENY");
    headers.emplace("Content-Security-Policy", "frame-ancestors 'none';");
    response->write(SimpleWeb::StatusCode::success_ok, in, headers);
  }

  /**
   * @brief Get the Sunshine logo image.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * @todo combine function with getFaviconImage and possibly getNodeModules
   * @todo use mime_types map
   */
  void getSunshineLogoImage(const resp_https_t &response, const req_https_t &request) {
    print_req(request);

    std::ifstream in(WEB_DIR "images/logo-sunshine-45.png", std::ios::binary);
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "image/png");
    headers.emplace("X-Frame-Options", "DENY");
    headers.emplace("Content-Security-Policy", "frame-ancestors 'none';");
    response->write(SimpleWeb::StatusCode::success_ok, in, headers);
  }

  /**
   * @brief Check if a path is a child of another path.
   * @param base The base path.
   * @param query The path to check.
   * @return True if the path is a child of the base path, false otherwise.
   */
  bool isChildPath(fs::path const &base, fs::path const &query) {
    auto relPath = fs::relative(base, query);
    return *(relPath.begin()) != fs::path("..");
  }

  /**
   * @brief Get an asset.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   */
  void getAsset(const resp_https_t &response, const req_https_t &request) {
    print_req(request);
    fs::path webDirPath(WEB_DIR);
    fs::path nodeModulesPath(webDirPath / "assets");

    // .relative_path is needed to shed any leading slash that might exist in the request path
    auto filePath = fs::weakly_canonical(webDirPath / fs::path(request->path).relative_path());

    // Don't do anything if the file does not exist or is outside the assets directory
    if (!isChildPath(filePath, nodeModulesPath)) {
      BOOST_LOG(warning) << "Someone requested a path " << filePath << " that is outside the assets folder";
      bad_request(response, request);
      return;
    }
    if (!fs::exists(filePath)) {
      not_found(response, request);
      return;
    }

    auto relPath = fs::relative(filePath, webDirPath);
    // get the mime type from the file extension mime_types map
    // remove the leading period from the extension
    auto mimeType = mime_types.find(relPath.extension().string().substr(1));
    // check if the extension is in the map at the x position
    if (mimeType == mime_types.end()) {
      bad_request(response, request);
      return;
    }

    // if it is, set the content type to the mime type
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", mimeType->second);
    headers.emplace("X-Frame-Options", "DENY");
    headers.emplace("Content-Security-Policy", "frame-ancestors 'none';");
    std::ifstream in(filePath.string(), std::ios::binary);
    response->write(SimpleWeb::StatusCode::success_ok, in, headers);
  }

  /**
   * @brief Get a CSRF token for the authenticated user.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/csrf-token| GET| null}
   */
  void getCSRFToken(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    print_req(request);

    std::string client_id = get_client_id(request);
    std::string token = generate_csrf_token(client_id);

    nlohmann::json output_tree;
    output_tree["csrf_token"] = token;
    send_response(response, output_tree);
  }

  /**
   * @brief Get the list of available applications.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/apps| GET| null}
   */
  void getApps(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    print_req(request);

    try {
      std::string content = file_handler::read_file(config::stream.file_apps.c_str());
      nlohmann::json file_tree = nlohmann::json::parse(content);

      // Legacy versions of Sunshine used strings for boolean and integers, let's convert them
      // List of keys to convert to boolean
      const std::vector<std::string> boolean_keys = {
        "exclude-global-prep-cmd",
        "elevated",
        "auto-detach",
        "wait-all"
      };

      // List of keys to convert to integers
      std::vector<std::string> integer_keys = {
        "exit-timeout"
      };

      // Walk fileTree and convert true/false strings to boolean or integer values
      for (auto &app : file_tree["apps"]) {
        for (const auto &key : boolean_keys) {
          if (app.contains(key) && app[key].is_string()) {
            app[key] = app[key] == "true";
          }
        }
        for (const auto &key : integer_keys) {
          if (app.contains(key) && app[key].is_string()) {
            app[key] = std::stoi(app[key].get<std::string>());
          }
        }
        if (app.contains("prep-cmd")) {
          for (auto &prep : app["prep-cmd"]) {
            if (prep.contains("elevated") && prep["elevated"].is_string()) {
              prep["elevated"] = prep["elevated"] == "true";
            }
          }
        }
      }

      send_response(response, file_tree);
    } catch (std::exception &e) {
      BOOST_LOG(warning) << "GetApps: "sv << e.what();
      bad_request(response, request, e.what());
    }
  }

  /**
   * @brief Save an application. To save a new application, the index must be `-1`. To update an existing application, you must provide the current index of the application.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * The body for the post request should be JSON serialized in the following format:
   * @code{.json}
   * {
   *   "name": "Application Name",
   *   "output": "Log Output Path",
   *   "cmd": "Command to run the application",
   *   "index": -1,
   *   "exclude-global-prep-cmd": false,
   *   "elevated": false,
   *   "auto-detach": true,
   *   "wait-all": true,
   *   "exit-timeout": 5,
   *   "prep-cmd": [
   *     {
   *       "do": "Command to prepare",
   *       "undo": "Command to undo preparation",
   *       "elevated": false
   *     }
   *   ],
   *   "detached": [
   *     "Detached command"
   *   ],
   *   "image-path": "Full path to the application image. Must be a png file."
   * }
   * @endcode
   *
   * @api_examples{/api/apps| POST| {"name":"Hello, World!","index":-1}}
   */
  void saveApp(const resp_https_t &response, const req_https_t &request) {
    if (!check_content_type(response, request, "application/json")) {
      return;
    }
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    std::stringstream ss;
    ss << request->content.rdbuf();
    try {
      // TODO: Input Validation
      nlohmann::json output_tree;
      nlohmann::json input_tree = nlohmann::json::parse(ss);
      std::string file = file_handler::read_file(config::stream.file_apps.c_str());
      BOOST_LOG(info) << file;
      nlohmann::json file_tree = nlohmann::json::parse(file);

      if (input_tree["prep-cmd"].empty()) {
        input_tree.erase("prep-cmd");
      }

      if (input_tree["detached"].empty()) {
        input_tree.erase("detached");
      }

      auto &apps_node = file_tree["apps"];
      int index = input_tree["index"].get<int>();  // this will intentionally cause an exception if the provided value is the wrong type

      input_tree.erase("index");

      if (index == -1) {
        apps_node.push_back(input_tree);
      } else {
        nlohmann::json newApps = nlohmann::json::array();
        for (size_t i = 0; i < apps_node.size(); ++i) {
          if (i == index) {
            newApps.push_back(input_tree);
          } else {
            newApps.push_back(apps_node[i]);
          }
        }
        file_tree["apps"] = newApps;
      }

      // Sort the apps array by name
      std::sort(apps_node.begin(), apps_node.end(), [](const nlohmann::json &a, const nlohmann::json &b) {
        return a["name"].get<std::string>() < b["name"].get<std::string>();
      });

      file_handler::write_file(config::stream.file_apps.c_str(), file_tree.dump(4));
      proc::refresh(config::stream.file_apps);

      output_tree["status"] = true;
      send_response(response, output_tree);
    } catch (std::exception &e) {
      BOOST_LOG(warning) << "SaveApp: "sv << e.what();
      bad_request(response, request, e.what());
    }
  }

  /**
   * @brief Close the currently running application.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/apps/close| POST| null}
   */
  void closeApp(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    proc::proc.terminate();

    nlohmann::json output_tree;
    output_tree["status"] = true;
    send_response(response, output_tree);
  }

  /**
   * @brief Delete an application.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/apps/9999| DELETE| null}
   */
  void deleteApp(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    try {
      nlohmann::json output_tree;
      nlohmann::json new_apps = nlohmann::json::array();
      const int index = std::stoi(request->path_match[1]);

      if (!check_app_index(response, request, index)) {
        return;
      }

      std::string file = file_handler::read_file(config::stream.file_apps.c_str());
      nlohmann::json file_tree = nlohmann::json::parse(file);
      auto &apps = file_tree["apps"];

      for (size_t i = 0; i < apps.size(); ++i) {
        if (i != index) {
          new_apps.push_back(apps[i]);
        }
      }
      file_tree["apps"] = new_apps;

      file_handler::write_file(config::stream.file_apps.c_str(), file_tree.dump(4));
      proc::refresh(config::stream.file_apps);

      output_tree["status"] = true;
      output_tree["result"] = std::format("application {} deleted", index);
      send_response(response, output_tree);
    } catch (std::exception &e) {
      BOOST_LOG(warning) << "DeleteApp: "sv << e.what();
      bad_request(response, request, e.what());
    }
  }

  /**
   * @brief Get the list of paired clients.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/clients/list| GET| null}
   */
  void getClients(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    print_req(request);

    const nlohmann::json named_certs = nvhttp::get_all_clients();

    nlohmann::json output_tree;
    output_tree["named_certs"] = named_certs;
    output_tree["status"] = true;
    send_response(response, output_tree);
  }

  /**
   * @brief Enable or disable a client.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * The body for the POST request should be JSON serialized in the following format:
   * @code{.json}
   * {
   *   "uuid": "<uuid>",
   *   "enabled": true
   * }
   * @endcode
   *
   * @api_examples{/api/clients/update| POST| {"uuid":"<uuid>","enabled":true}}
   */
  void updateClient(resp_https_t response, req_https_t request) {
    if (!check_content_type(response, request, "application/json")) {
      return;
    }
    if (!authenticate(response, request)) {
      return;
    }
    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    std::stringstream ss;
    ss << request->content.rdbuf();
    try {
      nlohmann::json input_tree = nlohmann::json::parse(ss.str());
      nlohmann::json output_tree;
      std::string uuid = input_tree.value("uuid", "");
      bool enabled = input_tree.value("enabled", true);
      output_tree["status"] = nvhttp::set_client_enabled(uuid, enabled);

      if (!enabled && output_tree["status"]) {
        auto cert = nvhttp::get_cert_by_uuid(uuid);
        if (!cert.empty()) {
          rtsp_stream::terminate_sessions_by_cert(cert);
        }

        if (rtsp_stream::session_count() == 0 && proc::proc.running() > 0) {
          proc::proc.terminate();
        }
      }

      send_response(response, output_tree);
    } catch (nlohmann::json::exception &e) {
      BOOST_LOG(warning) << "Update Client: "sv << e.what();
      bad_request(response, request, e.what());
    }
  }

  /**
   * @brief Unpair a client.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * The body for the POST request should be JSON serialized in the following format:
   * @code{.json}
   * {
   *  "uuid": "<uuid>"
   * }
   * @endcode
   *
   * @api_examples{/api/unpair| POST| {"uuid":"1234"}}
   */
  void unpair(const resp_https_t &response, const req_https_t &request) {
    if (!check_content_type(response, request, "application/json")) {
      return;
    }
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    std::stringstream ss;
    ss << request->content.rdbuf();

    try {
      // TODO: Input Validation
      nlohmann::json output_tree;
      const nlohmann::json input_tree = nlohmann::json::parse(ss);
      const std::string uuid = input_tree.value("uuid", "");
      const bool removed = nvhttp::unpair_client(uuid);
      output_tree["status"] = removed;

      if (removed && nvhttp::get_all_clients().empty()) {
        proc::proc.terminate();
      }

      send_response(response, output_tree);
    } catch (std::exception &e) {
      BOOST_LOG(warning) << "Unpair: "sv << e.what();
      bad_request(response, request, e.what());
    }
  }

  /**
   * @brief Unpair all clients.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/clients/unpair-all| POST| null}
   */
  void unpairAll(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    nvhttp::erase_all_clients();
    proc::proc.terminate();

    nlohmann::json output_tree;
    output_tree["status"] = true;
    send_response(response, output_tree);
  }

  /**
   * @brief Get the configuration settings.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/config| GET| null}
   */
  void getConfig(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    print_req(request);

    nlohmann::json output_tree;
    output_tree["status"] = true;
    output_tree["platform"] = SUNSHINE_PLATFORM;
    output_tree["version"] = PROJECT_VERSION;

    auto vars = config::parse_config(file_handler::read_file(config::sunshine.config_file.c_str()));

    for (auto &[name, value] : vars) {
      output_tree[name] = std::move(value);
    }

    send_response(response, output_tree);
  }

  /**
   * @brief Get the locale setting. This endpoint does not require authentication.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/configLocale| GET| null}
   */
  void getLocale(const resp_https_t &response, const req_https_t &request) {
    // we need to return the locale whether authenticated or not

    print_req(request);

    nlohmann::json output_tree;
    output_tree["status"] = true;
    output_tree["locale"] = config::sunshine.locale;
    send_response(response, output_tree);
  }

  /**
   * @brief Save the configuration settings.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * The body for the POST request should be JSON serialized in the following format:
   * @code{.json}
   * {
   *   "key": "value"
   * }
   * @endcode
   *
   * @attention{It is recommended to ONLY save the config settings that differ from the default behavior.}
   *
   * @api_examples{/api/config| POST| {"key":"value"}}
   */
  void saveConfig(const resp_https_t &response, const req_https_t &request) {
    if (!check_content_type(response, request, "application/json")) {
      return;
    }
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    std::stringstream ss;
    ss << request->content.rdbuf();
    try {
      // TODO: Input Validation
      std::stringstream config_stream;
      nlohmann::json output_tree;
      nlohmann::json input_tree = nlohmann::json::parse(ss);
      for (const auto &[k, v] : input_tree.items()) {
        if (v.is_null() || (v.is_string() && v.get<std::string>().empty())) {
          continue;
        }

        // v.dump() will dump valid json, which we do not want for strings in the config, right now
        // we should migrate the config file to straight JSON and get rid of all this nonsense
        config_stream << k << " = " << (v.is_string() ? v.get<std::string>() : v.dump()) << std::endl;
      }
      file_handler::write_file(config::sunshine.config_file.c_str(), config_stream.str());
      output_tree["status"] = true;
      send_response(response, output_tree);
    } catch (std::exception &e) {
      BOOST_LOG(warning) << "SaveConfig: "sv << e.what();
      bad_request(response, request, e.what());
    }
  }

  /**
   * @brief Get an application's image.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @note{The index in the url path is the application index.}
   *
   * @api_examples{/api/covers/9999 | GET| null}
   */
  void getCover(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    print_req(request);

    try {
      const int index = std::stoi(request->path_match[1]);
      if (!check_app_index(response, request, index)) {
        return;
      }

      std::string file = file_handler::read_file(config::stream.file_apps.c_str());
      nlohmann::json file_tree = nlohmann::json::parse(file);
      auto &apps = file_tree["apps"];

      auto &app = apps[index];

      // Get the image path from the app configuration
      std::string app_image_path;
      if (app.contains("image-path") && !app["image-path"].is_null()) {
        app_image_path = app["image-path"];
      }

      // Use validate_app_image_path to resolve and validate the path
      // This handles extension validation, PNG signature validation, and path resolution
      std::string validated_path = proc::validate_app_image_path(app_image_path);

      // Check if we got the default image path (means validation failed or no image configured)
      if (validated_path == DEFAULT_APP_IMAGE_PATH) {
        BOOST_LOG(debug) << "Application at index " << index << " does not have a valid cover image";
        not_found(response, request, "Cover image not found");
        return;
      }

      // Open and stream the validated file
      std::ifstream in(validated_path, std::ios::binary);
      if (!in) {
        BOOST_LOG(warning) << "Unable to read cover image file: " << validated_path;
        bad_request(response, request, "Unable to read cover image file");
        return;
      }

      SimpleWeb::CaseInsensitiveMultimap headers;
      headers.emplace("Content-Type", "image/png");
      headers.emplace("X-Frame-Options", "DENY");
      headers.emplace("Content-Security-Policy", "frame-ancestors 'none';");

      response->write(SimpleWeb::StatusCode::success_ok, in, headers);
    } catch (std::exception &e) {
      BOOST_LOG(warning) << "GetCover: "sv << e.what();
      bad_request(response, request, e.what());
    }
  }

  /**
   * @brief Upload a cover image.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * The body for the post request should be JSON serialized in the following format:
   * @code{.json}
   * {
   *   "key": "igdb_<game_id>",
   *   "url": "https://images.igdb.com/igdb/image/upload/t_cover_big_2x/<slug>.png"
   * }
   * @endcode
   *
   * @api_examples{/api/covers/upload| POST| {"key":"igdb_1234","url":"https://images.igdb.com/igdb/image/upload/t_cover_big_2x/abc123.png"}}
   */
  void uploadCover(const resp_https_t &response, const req_https_t &request) {
    if (!check_content_type(response, request, "application/json")) {
      return;
    }
    if (!authenticate(response, request)) {
      return;
    }

    std::stringstream ss;
    ss << request->content.rdbuf();
    try {
      nlohmann::json output_tree;
      nlohmann::json input_tree = nlohmann::json::parse(ss);

      std::string key = input_tree.value("key", "");
      if (key.empty()) {
        bad_request(response, request, "Cover key is required");
        return;
      }
      std::string url = input_tree.value("url", "");

      const std::string coverdir = platf::appdata().string() + "/covers/";
      file_handler::make_directory(coverdir);

      std::basic_string path = coverdir + http::url_escape(key) + ".png";
      if (!url.empty()) {
        if (http::url_get_host(url) != "images.igdb.com") {
          bad_request(response, request, "Only images.igdb.com is allowed");
          return;
        }
        if (!http::download_file(url, path)) {
          bad_request(response, request, "Failed to download cover");
          return;
        }
      } else {
        auto data = SimpleWeb::Crypto::Base64::decode(input_tree.value("data", ""));

        std::ofstream imgfile(path);
        imgfile.write(data.data(), static_cast<int>(data.size()));
      }
      output_tree["status"] = true;
      output_tree["path"] = path;
      send_response(response, output_tree);
    } catch (std::exception &e) {
      BOOST_LOG(warning) << "UploadCover: "sv << e.what();
      bad_request(response, request, e.what());
    }
  }

  /**
   * @brief Get the logs from the log file.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/logs| GET| null}
   */
  void getLogs(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    print_req(request);

    std::string content = file_handler::read_file(config::sunshine.log_file.c_str());
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "text/plain");
    headers.emplace("X-Frame-Options", "DENY");
    headers.emplace("Content-Security-Policy", "frame-ancestors 'none';");
    response->write(SimpleWeb::StatusCode::success_ok, content, headers);
  }

  /**
   * @brief Update existing credentials.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * The body for the post request should be JSON serialized in the following format:
   * @code{.json}
   * {
   *   "currentUsername": "Current Username",
   *   "currentPassword": "Current Password",
   *   "newUsername": "New Username",
   *   "newPassword": "New Password",
   *   "confirmNewPassword": "Confirm New Password"
   * }
   * @endcode
   *
   * @api_examples{/api/password| POST| {"currentUsername":"admin","currentPassword":"admin","newUsername":"admin","newPassword":"admin","confirmNewPassword":"admin"}}
   */
  void savePassword(const resp_https_t &response, const req_https_t &request) {
    if (!check_content_type(response, request, "application/json")) {
      return;
    }
    if (!config::sunshine.username.empty() && !authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    std::vector<std::string> errors = {};
    std::stringstream ss;
    std::stringstream config_stream;
    ss << request->content.rdbuf();
    try {
      // TODO: Input Validation
      nlohmann::json output_tree;
      nlohmann::json input_tree = nlohmann::json::parse(ss);
      std::string username = input_tree.value("currentUsername", "");
      std::string newUsername = input_tree.value("newUsername", "");
      std::string password = input_tree.value("currentPassword", "");
      std::string newPassword = input_tree.value("newPassword", "");
      std::string confirmPassword = input_tree.value("confirmNewPassword", "");
      if (newUsername.empty()) {
        newUsername = username;
      }
      if (newUsername.empty()) {
        errors.emplace_back("Invalid Username");
      } else {
        auto hash = util::hex(crypto::hash(password + config::sunshine.salt)).to_string();
        if (config::sunshine.username.empty() || (boost::iequals(username, config::sunshine.username) && hash == config::sunshine.password)) {
          if (newPassword.empty() || newPassword != confirmPassword) {
            errors.emplace_back("Password Mismatch");
          } else {
            http::save_user_creds(config::sunshine.credentials_file, newUsername, newPassword);
            http::reload_user_creds(config::sunshine.credentials_file);
            output_tree["status"] = true;
          }
        } else {
          errors.emplace_back("Invalid Current Credentials");
        }
      }

      if (!errors.empty()) {
        // join the errors array
        std::string error = std::accumulate(errors.begin(), errors.end(), std::string(), [](const std::string &a, const std::string &b) {
          return a.empty() ? b : a + ", " + b;
        });
        bad_request(response, request, error);
        return;
      }

      send_response(response, output_tree);
    } catch (std::exception &e) {
      BOOST_LOG(warning) << "SavePassword: "sv << e.what();
      bad_request(response, request, e.what());
    }
  }

  /**
   * @brief Send a pin code to the host. The pin is generated from the Moonlight client during the pairing process.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * The body for the post request should be JSON serialized in the following format:
   * @code{.json}
   * {
   *   "pin": "<pin>",
   *   "name": "Friendly Client Name"
   * }
   * @endcode
   *
   * @api_examples{/api/pin| POST| {"pin":"1234","name":"My PC"}}
   */
  void savePin(const resp_https_t &response, const req_https_t &request) {
    if (!check_content_type(response, request, "application/json")) {
      return;
    }
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    std::stringstream ss;
    ss << request->content.rdbuf();
    try {
      nlohmann::json output_tree;
      nlohmann::json input_tree = nlohmann::json::parse(ss);
      const std::string name = input_tree.value("name", "");
      const std::string pin = input_tree.value("pin", "");

      int _pin = 0;
      _pin = std::stoi(pin);
      if (_pin < 0 || _pin > 9999) {
        bad_request(response, request, "PIN must be between 0000 and 9999");
      }

      output_tree["status"] = nvhttp::pin(pin, name);
      send_response(response, output_tree);
    } catch (std::exception &e) {
      BOOST_LOG(warning) << "SavePin: "sv << e.what();
      bad_request(response, request, e.what());
    }
  }

  /**
   * @brief Reset the display device persistence.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/reset-display-device-persistence| POST| null}
   */
  void resetDisplayDevicePersistence(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    nlohmann::json output_tree;
    output_tree["status"] = display_device::reset_persistence();
    send_response(response, output_tree);
  }

  /**
   * @brief Authenticate a Web UI request and restart the Sunshine process.
   *
   * @param response HTTP response used for authentication or CSRF failures.
   * @param request HTTP request carrying the client identity and CSRF token.
   *
   * @api_examples{/api/restart| POST| null}
   */
  void restart(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    // We may not return from this call
    platf::restart();
  }

  /**
   * @brief Get ViGEmBus driver version and installation status.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/vigembus/status| GET| null}
   */
  void getViGEmBusStatus(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    print_req(request);

    nlohmann::json output_tree;

#ifdef _WIN32
    std::string version_str;
    bool installed = false;
    bool version_compatible = false;

    // Check if ViGEmBus driver exists
    std::filesystem::path driver_path = std::filesystem::path(std::getenv("SystemRoot") ? std::getenv("SystemRoot") : "C:\\Windows") / "System32" / "drivers" / "ViGEmBus.sys";

    if (std::filesystem::exists(driver_path)) {
      installed = platf::getFileVersionInfo(driver_path, version_str);
      if (installed) {
        // Parse version string to check compatibility (>= 1.17.0.0)
        std::vector<std::string> version_parts;
        std::stringstream ss(version_str);
        std::string part;
        while (std::getline(ss, part, '.')) {
          version_parts.push_back(part);
        }

        if (version_parts.size() >= 2) {
          int major = std::stoi(version_parts[0]);
          int minor = std::stoi(version_parts[1]);
          version_compatible = (major > 1) || (major == 1 && minor >= 17);
        }
      }
    }

    output_tree["installed"] = installed;
    output_tree["version"] = version_str;
    output_tree["version_compatible"] = version_compatible;
    output_tree["packaged_version"] = VIGEMBUS_PACKAGED_VERSION;
#else
    output_tree["error"] = "ViGEmBus is only available on Windows";
    output_tree["installed"] = false;
    output_tree["version"] = "";
    output_tree["version_compatible"] = false;
    output_tree["packaged_version"] = "";
#endif

    send_response(response, output_tree);
  }

  /**
   * @brief Install ViGEmBus driver with elevated permissions.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/vigembus/install| POST| null}
   */
  void installViGEmBus(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    nlohmann::json output_tree;

#ifdef _WIN32
    // Get the path to the packaged ViGEmBus installer.
    const std::filesystem::path installer_path = platf::appdata().parent_path() / "third-party" / "vigembus_installer.exe";

    if (!std::filesystem::exists(installer_path)) {
      output_tree["status"] = false;
      output_tree["error"] = "ViGEmBus installer not found";
      send_response(response, output_tree);
      return;
    }

    // Run the installer with elevated permissions
    std::error_code ec;
    boost::filesystem::path working_dir = boost::filesystem::path(installer_path.string()).parent_path();
    boost::process::v1::environment env = boost::this_process::environment();

    // Run with elevated permissions, non-interactive
    const std::string install_cmd = std::format("{} /quiet", installer_path.string());
    auto child = platf::run_command(true, false, install_cmd, working_dir, env, nullptr, ec, nullptr);

    if (ec) {
      output_tree["status"] = false;
      output_tree["error"] = "Failed to start installer: " + ec.message();
      send_response(response, output_tree);
      return;
    }

    // Wait for the installer to complete
    child.wait(ec);

    if (ec) {
      output_tree["status"] = false;
      output_tree["error"] = "Installer failed: " + ec.message();
    } else {
      int exit_code = child.exit_code();
      output_tree["status"] = (exit_code == 0);
      output_tree["exit_code"] = exit_code;
      if (exit_code != 0) {
        output_tree["error"] = std::format("Installer exited with code {}", exit_code);
      }
    }
#else
    output_tree["status"] = false;
    output_tree["error"] = "ViGEmBus installation is only available on Windows";
#endif

    send_response(response, output_tree);
  }

#ifdef _WIN32
  /** @brief Setup class GUID for the Keyboard device class. */
  constexpr GUID class_guid_keyboard {0x4d36e96b, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}};
  /** @brief Setup class GUID for the Mouse device class. */
  constexpr GUID class_guid_mouse {0x4d36e96f, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}};
  /** @brief Setup class GUID for the Monitor device class (informational only; never disabled). */
  constexpr GUID class_guid_monitor {0x4d36e96e, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}};

  /**
   * @brief True while the physical display is being kept in standby.
   */
  std::atomic<bool> monitor_off_active {false};

  /**
   * @brief Convert a wide (UTF-16) string to UTF-8.
   * @param value Null-terminated wide string; may be null.
   * @return UTF-8 encoded string (empty when @p value is null or empty).
   */
  std::string wide_to_utf8(const wchar_t *value) {
    if (!value || !*value) {
      return {};
    }
    const int size = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 1) {
      return {};
    }
    std::string result(static_cast<size_t>(size - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, -1, result.data(), size, nullptr, nullptr);
    return result;
  }

  /**
   * @brief A physical input device enumerated from a Windows setup class.
   */
  struct input_device_t {
    std::string instance_id;  ///< Device instance ID (for example `HID\VID_046D&PID_C31C\...`).
    std::string name;         ///< Friendly device name.
    DEVINST devinst;          ///< Device node handle bound to the local machine.
    bool disabled;            ///< True when the device is currently disabled.
    bool disableable;         ///< True when the device reports that it can be disabled.
  };

  /**
   * @brief Extract a VID wildcard (for example `*VID_046D*`) from a device instance ID.
   * @param instance_id Device instance ID.
   * @return Wildcard pattern, or an empty string when the ID contains no `VID_xxxx`.
   */
  std::string extract_vid_pattern(const std::string &instance_id) {
    std::regex vid_regex("VID_([0-9A-Fa-f]{4})");
    std::smatch match;
    if (std::regex_search(instance_id, match, vid_regex)) {
      return "*VID_" + match[1].str() + "*";
    }
    return {};
  }

  /** Setup class GUID for the USB device class (used to find disabled bus parents). */
  constexpr GUID class_guid_usb {0x36fc9e60, 0xc465, 0x11cf, {0x80, 0x56, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}};
  /** Setup class GUID for the HID device class (used to find disabled HID nodes). */
  constexpr GUID class_guid_hid {0x745a17a0, 0x74d3, 0x11d0, {0xb6, 0xfe, 0x00, 0xa0, 0xc9, 0x0f, 0x57, 0xda}};

  // Device registry property ids for CM_Get_DevNode_Registry_Property.
  constexpr ULONG drp_compatible_ids = 0x00000003;
  constexpr ULONG drp_service = 0x00000005;
  constexpr ULONG drp_config_flags = 0x0000000B;
  constexpr ULONG drp_friendly_name = 0x0000000D;

  // Device problem codes / flags for the eject-remove block (fallbacks if the SDK omits them).
#ifndef CM_PROB_WILL_BE_REMOVED
  #define CM_PROB_WILL_BE_REMOVED 0x00000015
#endif
#ifndef CM_PROB_HELD_FOR_EJECT
  #define CM_PROB_HELD_FOR_EJECT 0x0000002F
#endif
#ifndef CM_REMOVE_UI_NOT_OK
  #define CM_REMOVE_UI_NOT_OK 0x00000001
#endif
#ifndef CM_GET_DEVICE_INTERFACE_LIST_PRESENT
  #define CM_GET_DEVICE_INTERFACE_LIST_PRESENT 0x00000000
#endif

  /**
   * @brief Get the device instance ID string for a device node.
   */
  std::string device_instance_id(DEVINST devinst) {
    wchar_t id[1024] {};
    if (CM_Get_Device_IDW(devinst, id, ARRAYSIZE(id), 0) != CR_SUCCESS) {
      return {};
    }
    return wide_to_utf8(id);
  }

  /**
   * @brief Read a REG_MULTI_SZ device registry property.
   */
  std::vector<std::wstring> device_multi_sz_property(DEVINST devinst, ULONG property) {
    std::vector<std::wstring> result;

    ULONG size = 0;
    if (CM_Get_DevNode_Registry_PropertyW(devinst, property, nullptr, nullptr, &size, 0) != CR_SUCCESS || size == 0) {
      return result;
    }

    std::vector<wchar_t> buffer(size / sizeof(wchar_t) + 1, L'\0');
    if (CM_Get_DevNode_Registry_PropertyW(devinst, property, nullptr, buffer.data(), &size, 0) != CR_SUCCESS) {
      return result;
    }

    const wchar_t *cursor = buffer.data();
    while (*cursor) {
      result.emplace_back(cursor);
      cursor += result.back().size() + 1;
    }
    return result;
  }

  /**
   * @brief Read a REG_SZ device registry property.
   */
  std::string device_string_property(DEVINST devinst, ULONG property) {
    ULONG size = 0;
    if (CM_Get_DevNode_Registry_PropertyW(devinst, property, nullptr, nullptr, &size, 0) != CR_SUCCESS || size == 0) {
      return {};
    }
    std::vector<wchar_t> buffer(size / sizeof(wchar_t) + 1, L'\0');
    if (CM_Get_DevNode_Registry_PropertyW(devinst, property, nullptr, buffer.data(), &size, 0) != CR_SUCCESS) {
      return {};
    }
    return wide_to_utf8(buffer.data());
  }

  /**
   * @brief Whether a device node reports a given problem code.
   */
  bool node_problem_is(DEVINST devinst, ULONG wanted) {
    ULONG status = 0;
    ULONG problem = 0;
    return CM_Get_DevNode_Status(&status, &problem, devinst, 0) == CR_SUCCESS &&
           (status & DN_HAS_PROBLEM) != 0 && problem == wanted;
  }

  /**
   * @brief Whether a device node is currently disabled (problem code 22).
   */
  bool node_is_disabled(DEVINST devinst) {
    return node_problem_is(devinst, CM_PROB_DISABLED);
  }

  /** @brief True when the node was marked for removal (eject/remove block, code 21). */
  bool node_is_removed(DEVINST devinst) {
    return node_problem_is(devinst, CM_PROB_WILL_BE_REMOVED);
  }

  /** @brief True when the node is held for eject (eject block, code 47). */
  bool node_is_ejected(DEVINST devinst) {
    return node_problem_is(devinst, CM_PROB_HELD_FOR_EJECT);
  }

  /** @brief True when the node is blocked by any block method (disabled, removed, ejected). */
  bool node_is_blocked(DEVINST devinst) {
    return node_is_disabled(devinst) || node_is_removed(devinst) || node_is_ejected(devinst);
  }

  /** @brief Instance id of a device node's parent (empty when root). */
  std::string parent_instance_id(DEVINST devinst) {
    DEVINST parent = 0;
    if (CM_Get_Parent(&parent, devinst, 0) == CR_SUCCESS && parent != 0) {
      return device_instance_id(parent);
    }
    return {};
  }

  /** @brief Infer the active block method from a node's problem code. */
  std::string block_method(DEVINST devinst) {
    if (node_is_ejected(devinst)) {
      return "ejected";
    }
    if (node_is_removed(devinst)) {
      return "removed";
    }
    return "disabled";
  }

  /** @brief Device property key for the USB connection index (DEVPKEY_Device_Address). */
  constexpr DEVPROPKEY devpkey_device_address {
    {0xA45C254E, 0xDF1C, 0x4EFD, {0x80, 0x20, 0x67, 0xD1, 0x46, 0xA8, 0x50, 0xE0}},
    30
  };

  /** @brief Device interface GUID for USB hubs (GUID_DEVINTERFACE_USB_HUB). */
  constexpr GUID guid_devinterface_usb_hub {
    0xF18A0E88, 0xC30C, 0x11D0, {0x88, 0x15, 0x00, 0xA0, 0xC9, 0x06, 0xBE, 0xD8}
  };

  /** @brief Parameters for IOCTL_USB_HUB_CYCLE_PORT. */
  struct usb_cycle_port_params_t {
    ULONG ConnectionIndex;
    ULONG StatusReturned;
  };

  // CTL_CODE(FILE_DEVICE_USB=FILE_DEVICE_UNKNOWN=0x22, USB_HUB_CYCLE_PORT=273, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0).
  constexpr ULONG ioctl_usb_hub_cycle_port = 0x00220444;

  /**
   * @brief Reset the USB port a device is attached to (IOCTL_USB_HUB_CYCLE_PORT).
   * @details Reactivates a device held for eject (problem code 47). Walks up to the
   *          parent USB hub, then issues the hub cycle-port IOCTL for the device's
   *          connection index (port).
   * @return True when the hub accepted the port reset.
   */
  /** @brief Find the parent USB hub instance id and connection index (port) for a node. */
  bool find_hub_and_port(DEVINST devinst, std::string &hub_id, ULONG &connection_index) {
    DEVINST node = devinst;
    for (int depth = 0; depth < 16; ++depth) {
      const std::string service = device_string_property(node, drp_service);
      if (service.find("usbhub") != std::string::npos || service.find("USBHUB") != std::string::npos) {
        hub_id = device_instance_id(node);
        return true;
      }

      // The connection index is the address of the child below the hub.
      DEVPROPTYPE type = 0;
      ULONG size = sizeof(connection_index);
      CM_Get_DevNode_PropertyW(node, &devpkey_device_address, &type, reinterpret_cast<PBYTE>(&connection_index), &size, 0);

      DEVINST parent = 0;
      if (CM_Get_Parent(&parent, node, 0) != CR_SUCCESS || parent == 0) {
        break;
      }
      node = parent;
    }
    return false;
  }

  /** @brief Reset a specific USB hub port (IOCTL_USB_HUB_CYCLE_PORT). */
  bool cycle_port(const std::string &hub_id, ULONG connection_index) {
    if (hub_id.empty()) {
      return false;
    }

    std::wstring wide_hub(hub_id.begin(), hub_id.end());
    ULONG list_size = 0;
    if (CM_Get_Device_Interface_List_SizeW(&list_size, const_cast<LPGUID>(&guid_devinterface_usb_hub), wide_hub.data(), CM_GET_DEVICE_INTERFACE_LIST_PRESENT) != CR_SUCCESS || list_size == 0) {
      return false;
    }

    std::vector<wchar_t> list(list_size, L'\0');
    if (CM_Get_Device_Interface_ListW(const_cast<LPGUID>(&guid_devinterface_usb_hub), wide_hub.data(), list.data(), list_size, CM_GET_DEVICE_INTERFACE_LIST_PRESENT) != CR_SUCCESS) {
      return false;
    }

    HANDLE hub = CreateFileW(list.data(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hub == INVALID_HANDLE_VALUE) {
      return false;
    }
    auto close = util::fail_guard([hub]() {
      CloseHandle(hub);
    });

    usb_cycle_port_params_t params {};
    params.ConnectionIndex = connection_index;
    DWORD returned = 0;
    const BOOL ok = DeviceIoControl(hub, ioctl_usb_hub_cycle_port, &params, sizeof(params), &params, sizeof(params), &returned, nullptr);
    return ok != FALSE && params.StatusReturned == ERROR_SUCCESS;
  }

  /**
   * @brief Reset the USB port a device is attached to (IOCTL_USB_HUB_CYCLE_PORT).
   */
  bool usb_cycle_port(DEVINST devinst) {
    std::string hub_id;
    ULONG port = 0;
    if (!find_hub_and_port(devinst, hub_id, port)) {
      return false;
    }
    return cycle_port(hub_id, port);
  }

  /** @brief Trigger a global device rescan ("Scan for hardware changes"). */
  void rescan_devices() {
    std::error_code ec;
    boost::filesystem::path working_dir;
    boost::process::v1::environment env = boost::this_process::environment();
    auto child = platf::run_command(true, false, "pnputil /scan-devices", working_dir, env, nullptr, ec, nullptr);
    if (!ec && child.valid()) {
      child.wait(ec);
    }
  }

  /**
   * @brief Whether the node is a USB hub or root hub (never disable these).
   */
  bool is_usb_hub(DEVINST devinst) {
    // Root hubs (USB\ROOT_HUB20 / USB\ROOT_HUB30) do NOT carry a Class_09
    // compatible id, so match them by instance id too — a root hub must never be
    // disabled (that would take down every device on the controller).
    if (device_instance_id(devinst).rfind("USB\\ROOT_HUB", 0) == 0) {
      return true;
    }
    for (const auto &compatible_id : device_multi_sz_property(devinst, drp_compatible_ids)) {
      if (compatible_id.find(L"Class_09") != std::wstring::npos) {
        return true;
      }
    }
    return false;
  }

  /**
   * @brief Build the physical HID/USB ancestor chain for a HID collection.
   * @details Returns the chain from the collection up to the topmost `USB\VID_…`
   *          node (composite), or an empty vector if the device has no USB
   *          ancestor (virtual/root-enumerated, e.g. FakerInput). This is the
   *          physical-only gate: virtual devices are never targeted.
   */
  std::vector<DEVINST> build_physical_chain(DEVINST devinst) {
    std::vector<DEVINST> chain;
    bool physical = false;

    DEVINST current = devinst;
    for (int depth = 0; depth < 16; ++depth) {
      chain.push_back(current);

      DEVINST parent = 0;
      if (CM_Get_Parent(&parent, current, 0) != CR_SUCCESS || parent == 0) {
        break;
      }
      const std::string id = device_instance_id(parent);
      if (id.rfind("USB\\", 0) == 0) {
        // Only physical device/interface nodes (USB\VID_…) are valid targets;
        // stop at root hubs, hubs and host controllers so a root hub can never
        // become a target even if the Class_09 hub check misses it.
        if (id.rfind("USB\\VID_", 0) != 0 || is_usb_hub(parent)) {
          break;
        }
        physical = true;
      } else if (id.rfind("HID\\", 0) != 0) {
        break;  // left the HID/USB bus (PS/2, Bluetooth, virtual root, …)
      }
      current = parent;
    }

    return physical ? chain : std::vector<DEVINST> {};
  }

  /** @brief Problem codes that indicate a device is blocked by our input-block. */
  bool is_block_problem(ULONG problem) {
    return problem == CM_PROB_DISABLED || problem == CM_PROB_WILL_BE_REMOVED || problem == CM_PROB_HELD_FOR_EJECT;
  }

  /** @brief A USB/HID device node with its state, for status and healing. */
  struct device_info_t {
    DEVINST devinst = 0;
    std::string instance_id;
    std::string name;
    std::string service;
    std::string parent_id;
    ULONG problem = 0;        ///< CM problem code (0 = none).
    ULONG status = 0;         ///< CM status flags.
    DWORD config_flags = 0;   ///< Device ConfigFlags (CONFIGFLAG_DISABLED = 1).
    int depth = 0;            ///< Distance from the root (for top-down healing).
    bool root_hub = false;    ///< True for USB root hubs (never re-enumerated/cycled).
  };

  /**
   * @brief Enumerate all present USB and HID device nodes (including hidden ones).
   * @details Uses the device ID list for the USB and HID enumerators rather than the
   *          class scan, so devices hidden behind a disabled parent are still found.
   */
  std::vector<device_info_t> enumerate_usb_hid_devices() {
    std::vector<device_info_t> result;

    for (const wchar_t *enumerator : {L"USB", L"HID"}) {
      ULONG len = 0;
      if (CM_Get_Device_ID_List_SizeW(&len, enumerator, CM_GETIDLIST_FILTER_ENUMERATOR | CM_GETIDLIST_FILTER_PRESENT) != CR_SUCCESS || len == 0) {
        continue;
      }
      std::vector<wchar_t> buffer(len, L'\0');
      if (CM_Get_Device_ID_ListW(enumerator, buffer.data(), len, CM_GETIDLIST_FILTER_ENUMERATOR | CM_GETIDLIST_FILTER_PRESENT) != CR_SUCCESS) {
        continue;
      }

      for (const wchar_t *cursor = buffer.data(); *cursor;) {
        const std::wstring entry(cursor);
        cursor += entry.size() + 1;

        DEVINST devinst = 0;
        if (CM_Locate_DevNodeW(&devinst, const_cast<wchar_t *>(entry.c_str()), CM_LOCATE_DEVNODE_NORMAL) != CR_SUCCESS) {
          continue;
        }

        device_info_t info;
        info.devinst = devinst;
        info.instance_id = wide_to_utf8(entry.c_str());
        info.root_hub = info.instance_id.rfind("USB\\ROOT_HUB", 0) == 0;

        ULONG status = 0;
        ULONG problem = 0;
        if (CM_Get_DevNode_Status(&status, &problem, devinst, 0) == CR_SUCCESS) {
          info.status = status;
          info.problem = (status & DN_HAS_PROBLEM) ? problem : 0;
        }

        info.name = device_string_property(devinst, drp_friendly_name);
        if (info.name.empty()) {
          info.name = info.instance_id;
        }
        info.service = device_string_property(devinst, drp_service);
        info.parent_id = parent_instance_id(devinst);

        ULONG flags = 0;
        ULONG flags_size = sizeof(flags);
        if (CM_Get_DevNode_Registry_PropertyW(devinst, drp_config_flags, nullptr, reinterpret_cast<PBYTE>(&flags), &flags_size, 0) == CR_SUCCESS) {
          info.config_flags = flags;
        }

        for (DEVINST node = devinst; info.depth < 16;) {
          DEVINST parent = 0;
          if (CM_Get_Parent(&parent, node, 0) != CR_SUCCESS || parent == 0) {
            break;
          }
          info.depth++;
          node = parent;
        }

        result.push_back(std::move(info));
      }
    }

    return result;
  }

  /** @brief Serialize a device node to JSON for status/reports. */
  nlohmann::json device_info_to_json(const device_info_t &device) {
    return {
      {"instance_id", device.instance_id},
      {"name", device.name},
      {"service", device.service},
      {"parent", device.parent_id},
      {"problem", device.problem},
      {"config_flags", device.config_flags},
      {"disabled_flag", (device.config_flags & 1) != 0},
      {"depth", device.depth},
      {"root_hub", device.root_hub}
    };
  }

  /**
   * @brief Enumerate present, disabled HID/USB input nodes (bus parents/HID devices).
   * @details Used by unblock/self-heal because a disabled parent hides its child
   *          collections from the Keyboard/Mouse class enumeration.
   */
  std::vector<input_device_t> enumerate_disabled_hid_bus_nodes() {
    std::vector<input_device_t> devices;

    auto scan = [&](const GUID &class_guid, bool usb_only) {
      HDEVINFO set = SetupDiGetClassDevsW(&class_guid, nullptr, nullptr, DIGCF_PRESENT);
      if (set == INVALID_HANDLE_VALUE) {
        return;
      }
      auto set_free = util::fail_guard([set]() {
        SetupDiDestroyDeviceInfoList(set);
      });

      SP_DEVINFO_DATA info {};
      info.cbSize = sizeof(info);
      for (DWORD index = 0; SetupDiEnumDeviceInfo(set, index, &info); ++index) {
        wchar_t instance_id[1024] {};
        if (!SetupDiGetDeviceInstanceIdW(set, &info, instance_id, ARRAYSIZE(instance_id), nullptr)) {
          continue;
        }

        const std::string id = wide_to_utf8(instance_id);
        if (usb_only && id.rfind("USB\\", 0) != 0) {
          continue;
        }
        if (is_usb_hub(info.DevInst)) {
          continue;
        }

        const std::string service = device_string_property(info.DevInst, drp_service);
        if (service != "usbccgp" && service != "hidusb" && service != "usbhid") {
          continue;
        }

        input_device_t device;
        device.instance_id = id;
        wchar_t friendly_name[512] {};
        SetupDiGetDeviceRegistryPropertyW(set, &info, SPDRP_FRIENDLYNAME, nullptr, reinterpret_cast<PBYTE>(friendly_name), sizeof(friendly_name), nullptr);
        device.name = friendly_name[0] ? wide_to_utf8(friendly_name) : id;
        device.devinst = info.DevInst;
        device.disabled = node_is_blocked(info.DevInst);
        device.disableable = false;

        devices.push_back(std::move(device));
      }
    };

    scan(class_guid_usb, true);
    scan(class_guid_hid, false);

    return devices;
  }

  /**
   * @brief Enumerate present devices belonging to a Windows setup class.
   * @param class_guid Setup class GUID (for example @ref class_guid_keyboard).
   * @return Devices with their current enabled/disabled state.
   */
  std::vector<input_device_t> enumerate_input_class(const GUID &class_guid) {
    std::vector<input_device_t> devices;

    HDEVINFO set = SetupDiGetClassDevsW(&class_guid, nullptr, nullptr, DIGCF_PRESENT);
    if (set == INVALID_HANDLE_VALUE) {
      BOOST_LOG(warning) << "Input block: SetupDiGetClassDevs failed ["sv << GetLastError() << ']';
      return devices;
    }
    auto set_free = util::fail_guard([set]() {
      SetupDiDestroyDeviceInfoList(set);
    });

    SP_DEVINFO_DATA info {};
    info.cbSize = sizeof(info);
    for (DWORD index = 0; SetupDiEnumDeviceInfo(set, index, &info); ++index) {
      wchar_t instance_id[1024] {};
      if (!SetupDiGetDeviceInstanceIdW(set, &info, instance_id, ARRAYSIZE(instance_id), nullptr)) {
        continue;
      }

      wchar_t friendly_name[512] {};
      SetupDiGetDeviceRegistryPropertyW(set, &info, SPDRP_FRIENDLYNAME, nullptr, reinterpret_cast<PBYTE>(friendly_name), sizeof(friendly_name), nullptr);

      input_device_t device;
      device.instance_id = wide_to_utf8(instance_id);
      device.name = friendly_name[0] ? wide_to_utf8(friendly_name) : device.instance_id;
      device.devinst = info.DevInst;
      device.disabled = node_is_blocked(info.DevInst);
      device.disableable = false;

      ULONG status = 0;
      ULONG problem = 0;
      if (CM_Get_DevNode_Status(&status, &problem, info.DevInst, 0) == CR_SUCCESS) {
        device.disableable = (status & DN_DISABLEABLE) != 0;
      }

      devices.push_back(std::move(device));
    }

    return devices;
  }

  /**
   * @brief Serialize a list of input devices to JSON.
   * @param devices Devices to serialize.
   * @return JSON array with `instance_id`, `name`, `vid_pattern`, `disabled` and `disableable` fields.
   */
  nlohmann::json devices_to_json(const std::vector<input_device_t> &devices) {
    nlohmann::json result = nlohmann::json::array();
    for (const auto &device : devices) {
      result.push_back({
        {"instance_id", device.instance_id},
        {"name", device.name},
        {"vid_pattern", extract_vid_pattern(device.instance_id)},
        {"disabled", device.disabled},
        {"disableable", device.disableable}
      });
    }
    return result;
  }

  bool setupdi_set_state(DEVINST devinst, DWORD state_change);
  bool registry_enable(DEVINST devinst);
  bool restore_node(DEVINST devinst, bool force_cycle = false);

  /**
   * @brief Enable a single device node, restoring whichever block method was used
   *        (disable, remove, or eject). Returns a result string.
   */
  std::string enable_device(const input_device_t &device) {
    if (!device.disabled) {
      return "already_enabled";
    }
    if (restore_node(device.devinst)) {
      return "enabled";
    }

    BOOST_LOG(warning) << "Input unblock: could not enable "sv << device.name;
    return "error_enable";
  }

  /**
   * @brief Read the optional `dry_run` flag from a request body (default false).
   */
  bool request_dry_run(const req_https_t &request) {
    try {
      return nlohmann::json::parse(request->content.string()).value("dry_run", false);
    } catch (...) {
      return false;
    }
  }

  /**
   * @brief Set a device node's state via the class installer (Device Manager path).
   * @details Device Manager uses DIF_PROPERTYCHANGE / DICS_* rather than
   *          CM_Disable_DevNode, and can disable nodes that report
   *          CR_NOT_DISABLEABLE through the CM API.
   */
  bool setupdi_set_state(DEVINST devinst, DWORD state_change) {
    const std::string instance_id = device_instance_id(devinst);
    if (instance_id.empty()) {
      return false;
    }
    const std::wstring wide_id(instance_id.begin(), instance_id.end());

    HDEVINFO set = SetupDiCreateDeviceInfoList(nullptr, nullptr);
    if (set == INVALID_HANDLE_VALUE) {
      return false;
    }
    auto set_free = util::fail_guard([set]() {
      SetupDiDestroyDeviceInfoList(set);
    });

    SP_DEVINFO_DATA info {};
    info.cbSize = sizeof(info);
    if (!SetupDiOpenDeviceInfoW(set, wide_id.c_str(), nullptr, 0, &info)) {
      return false;
    }

    SP_PROPCHANGE_PARAMS params {};
    params.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
    params.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
    params.StateChange = state_change;
    params.Scope = DICS_FLAG_GLOBAL;
    params.HwProfile = 0;

    if (!SetupDiSetClassInstallParamsW(set, &info, &params.ClassInstallHeader, sizeof(params))) {
      return false;
    }
    return SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, set, &info) != FALSE;
  }

  /** @brief Verbose per-node logging (on for block/unblock; off for the watchdog). */
  std::atomic<bool> input_block_verbose {false};

  /**
   * @brief Re-enumerate a node and its parent synchronously so a registry
   *        ConfigFlags change actually takes effect (a plain async re-enumerate
   *        frequently does not — the flag is written but the device stays started).
   */
  void reenumerate_node(DEVINST devinst) {
    CM_Reenumerate_DevNode(devinst, CM_REENUMERATE_SYNCHRONOUS);
    DEVINST parent = 0;
    if (CM_Get_Parent(&parent, devinst, 0) == CR_SUCCESS && parent != 0) {
      CM_Reenumerate_DevNode(parent, CM_REENUMERATE_SYNCHRONOUS);
    }
  }

  /**
   * @brief Clear a forced registry disable (CONFIGFLAG_DISABLED) and re-enumerate.
   */
  bool registry_enable(DEVINST devinst) {
    HKEY key = nullptr;
    if (CM_Open_DevNode_Key(devinst, KEY_QUERY_VALUE | KEY_SET_VALUE, 0, RegDisposition_OpenExisting, &key, CM_REGISTRY_HARDWARE) != CR_SUCCESS) {
      return false;
    }

    DWORD flags = 0;
    DWORD size = sizeof(flags);
    DWORD type = 0;
    if (RegQueryValueExW(key, L"ConfigFlags", nullptr, &type, reinterpret_cast<LPBYTE>(&flags), &size) != ERROR_SUCCESS) {
      RegCloseKey(key);
      return false;
    }
    flags &= ~static_cast<DWORD>(0x00000001);  // clear CONFIGFLAG_DISABLED

    const bool ok = RegSetValueExW(key, L"ConfigFlags", 0, REG_DWORD, reinterpret_cast<const BYTE *>(&flags), sizeof(flags)) == ERROR_SUCCESS;
    RegCloseKey(key);

    if (ok) {
      reenumerate_node(devinst);
    }
    return ok;
  }

  /**
   * @brief Restore (unblock) a node blocked by any method.
   * @details Eject (problem code 47) needs the USB port reset; remove (code 21)
   *          and disable (code 22) need the device restarted/enabled.
   * @return True when the node is no longer blocked.
   */
  bool restore_node(DEVINST devinst, bool force_cycle) {
    if (force_cycle || node_is_ejected(devinst)) {
      usb_cycle_port(devinst);
    }

    CM_Enable_DevNode(devinst, 0);
    if (!node_is_blocked(devinst)) {
      return true;
    }

    reenumerate_node(devinst);
    if (!node_is_blocked(devinst)) {
      return true;
    }

    if (setupdi_set_state(devinst, DICS_ENABLE) && !node_is_blocked(devinst)) {
      return true;
    }

    if (registry_enable(devinst) && !node_is_blocked(devinst)) {
      return true;
    }

    // Re-enumeration is asynchronous: give the node a moment to clear its problem.
    for (int i = 0; i < 10 && node_is_blocked(devinst); ++i) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return !node_is_blocked(devinst);
  }

  /**
   * @brief Block a node by ejecting/removing it (problem codes 21/47).
   * @details A different API family than CM_Disable_DevNode: works on nodes that
   *          report CR_NOT_DISABLEABLE. CM_Query_And_Remove_SubTree marks the
   *          subtree for removal (code 21); CM_Request_Device_Eject holds the
   *          device for eject (code 47). Restore via restart / USB port reset.
   * @return `removed`, `ejected`, or `error_<code>`.
   */
  std::string eject_node(DEVINST devinst, const std::string &name) {
    // pVetoType / pszVetoName are optional; we only need the CONFIGRET.
    CONFIGRET cr = CM_Query_And_Remove_SubTreeW(devinst, nullptr, nullptr, 0, CM_REMOVE_UI_NOT_OK);
    if (cr == CR_SUCCESS || node_is_removed(devinst)) {
      return "removed";
    }

    cr = CM_Request_Device_EjectW(devinst, nullptr, nullptr, 0, 0);
    if (cr == CR_SUCCESS || node_is_ejected(devinst)) {
      return "ejected";
    }

    if (input_block_verbose.load()) {
      BOOST_LOG(info) << "Input block: eject/remove vetoed ["sv << static_cast<unsigned long>(cr) << "] "sv << name;
    }
    return std::format("error_{}", static_cast<unsigned long>(cr));
  }

  /**
   * @brief Heal a single blocked node (caller orders top-down).
   * @details Dispatches by problem code. Root hubs are only enabled, never
   *          re-enumerated or port-cycled.
   * @return A short action string.
   */
  std::string heal_one_device(const device_info_t &device) {
    if (device.root_hub) {
      if (device.problem == CM_PROB_DISABLED) {
        registry_enable(device.devinst);
        CM_Enable_DevNode(device.devinst, 0);
        return "enabled_root_hub";
      }
      return "skipped_root_hub";
    }

    switch (device.problem) {
      case CM_PROB_DISABLED:
        registry_enable(device.devinst);
        CM_Enable_DevNode(device.devinst, 0);
        reenumerate_node(device.devinst);
        return "enabled";
      case CM_PROB_WILL_BE_REMOVED:
        reenumerate_node(device.devinst);
        return "reenumerated";
      case CM_PROB_HELD_FOR_EJECT:
        usb_cycle_port(device.devinst);
        reenumerate_node(device.devinst);
        return "cycled_port";
      default:
        return "noop";
    }
  }

  /**
   * @brief Cascade-heal every blocked USB/HID device.
   * @details Re-scans after each pass because enabling a parent reveals disabled
   *          children. Runs at most @p max_passes times. Only ever enables devices.
   * @return A JSON report of each pass.
   */
  nlohmann::json heal_input_devices(int max_passes = 15) {
    nlohmann::json report = nlohmann::json::array();

    for (int pass = 1; pass <= max_passes; ++pass) {
      std::vector<device_info_t> blocked;
      for (const auto &device : enumerate_usb_hid_devices()) {
        if (is_block_problem(device.problem)) {
          blocked.push_back(device);
        }
      }

      nlohmann::json pass_report;
      pass_report["pass"] = pass;
      pass_report["blocked"] = blocked.size();

      if (blocked.empty()) {
        pass_report["clean"] = true;
        report.push_back(std::move(pass_report));
        break;
      }

      // Top-down: enable ancestors before descendants so hidden children appear next pass.
      std::sort(blocked.begin(), blocked.end(), [](const device_info_t &a, const device_info_t &b) {
        return a.depth < b.depth;
      });

      nlohmann::json acted = nlohmann::json::array();
      for (const auto &device : blocked) {
        const std::string action = heal_one_device(device);
        acted.push_back({{"instance_id", device.instance_id}, {"problem", device.problem}, {"action", action}});
        if (input_block_verbose.load()) {
          BOOST_LOG(info) << "Input heal: "sv << action << " "sv << device.instance_id << " (problem "sv << device.problem << ")"sv;
        }
      }
      pass_report["acted"] = std::move(acted);
      report.push_back(std::move(pass_report));

      std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }

    return report;
  }

  /** @brief Registry location recording blocked target instance ids. */
  constexpr wchar_t input_block_state_key[] = L"SOFTWARE\\LegionGames\\Sunshine\\InputBlock";

  /**
   * @brief A recorded blocked target (instance id + method + parent, for restore).
   */
  struct blocked_target_t {
    std::string instance_id;  ///< Device instance ID that was blocked.
    std::string method;       ///< `disabled`, `removed`, or `ejected`.
    std::string parent_id;    ///< Parent (hub) instance ID, for re-enumeration restore.
    std::string hub_id;       ///< USB hub instance ID owning the port (for a port cycle).
    ULONG port = 0;           ///< Connection index (port) on that hub.
  };

  /**
   * @brief Read the recorded blocked targets.
   * @details Entries are stored as `<instance_id>\t<method>\t<parent_id>`. Legacy
   *          entries (plain instance ids from earlier versions) are treated as
   *          `disabled` with no parent.
   */
  std::vector<blocked_target_t> read_blocked_targets() {
    std::vector<blocked_target_t> result;

    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, input_block_state_key, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
      return result;
    }

    DWORD type = 0;
    DWORD size = 0;
    if (RegQueryValueExW(key, L"DisabledTargets", nullptr, &type, nullptr, &size) == ERROR_SUCCESS && size >= sizeof(wchar_t)) {
      std::vector<wchar_t> buffer(size / sizeof(wchar_t) + 1, L'\0');
      if (RegQueryValueExW(key, L"DisabledTargets", nullptr, &type, reinterpret_cast<LPBYTE>(buffer.data()), &size) == ERROR_SUCCESS) {
        const wchar_t *cursor = buffer.data();
        while (*cursor) {
          const std::wstring entry(cursor);
          blocked_target_t target;
          const auto first = entry.find(L'\t');
          if (first == std::wstring::npos) {
            target.instance_id = wide_to_utf8(cursor);
          } else {
            const auto second = entry.find(L'\t', first + 1);
            const auto third = (second == std::wstring::npos) ? std::wstring::npos : entry.find(L'\t', second + 1);
            const auto fourth = (third == std::wstring::npos) ? std::wstring::npos : entry.find(L'\t', third + 1);
            target.instance_id = wide_to_utf8(entry.substr(0, first).c_str());
            const auto method = entry.substr(first + 1, second == std::wstring::npos ? std::wstring::npos : second - first - 1);
            target.method = wide_to_utf8(method.c_str());
            if (second != std::wstring::npos) {
              target.parent_id = wide_to_utf8(entry.substr(second + 1, third == std::wstring::npos ? std::wstring::npos : third - second - 1).c_str());
            }
            if (third != std::wstring::npos) {
              target.hub_id = wide_to_utf8(entry.substr(third + 1, fourth == std::wstring::npos ? std::wstring::npos : fourth - third - 1).c_str());
            }
            if (fourth != std::wstring::npos) {
              try {
                target.port = static_cast<ULONG>(std::stoul(wide_to_utf8(entry.substr(fourth + 1).c_str())));
              } catch (...) {}
            }
          }
          if (target.method.empty()) {
            target.method = "disabled";
          }
          result.push_back(std::move(target));
          cursor += entry.size() + 1;
        }
      }
    }
    RegCloseKey(key);
    return result;
  }

  /**
   * @brief Write (or clear) the recorded blocked targets.
   */
  void write_blocked_targets(const std::vector<blocked_target_t> &targets) {
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, input_block_state_key, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
      return;
    }

    if (targets.empty()) {
      RegDeleteValueW(key, L"DisabledTargets");
    } else {
      std::vector<wchar_t> buffer;
      for (const auto &target : targets) {
        const std::wstring wide(target.instance_id.begin(), target.instance_id.end());
        const std::wstring method(target.method.begin(), target.method.end());
        const std::wstring parent(target.parent_id.begin(), target.parent_id.end());
        const std::wstring hub(target.hub_id.begin(), target.hub_id.end());
        const std::wstring port(std::to_wstring(target.port));
        buffer.insert(buffer.end(), wide.begin(), wide.end());
        buffer.push_back(L'\t');
        buffer.insert(buffer.end(), method.begin(), method.end());
        buffer.push_back(L'\t');
        buffer.insert(buffer.end(), parent.begin(), parent.end());
        buffer.push_back(L'\t');
        buffer.insert(buffer.end(), hub.begin(), hub.end());
        buffer.push_back(L'\t');
        buffer.insert(buffer.end(), port.begin(), port.end());
        buffer.push_back(L'\0');
      }
      buffer.push_back(L'\0');
      RegSetValueExW(key, L"DisabledTargets", 0, REG_MULTI_SZ, reinterpret_cast<const BYTE *>(buffer.data()), static_cast<DWORD>(buffer.size() * sizeof(wchar_t)));
    }
    RegCloseKey(key);
  }

  /**
   * @brief Record a blocked target (idempotent by instance id).
   */
  void add_blocked_target(const blocked_target_t &target) {
    auto targets = read_blocked_targets();
    for (const auto &existing : targets) {
      if (existing.instance_id == target.instance_id) {
        return;
      }
    }
    targets.push_back(target);
    write_blocked_targets(targets);
  }

  /**
   * @brief Restore a recorded blocked target (by instance id + method).
   * @return True when the target was restored (or re-enumerated via its parent).
   */
  bool restore_target(const blocked_target_t &target) {
    std::wstring wide(target.instance_id.begin(), target.instance_id.end());

    // Removed/ejected: the target's SUBTREE was removed, so its children (USB
    // interfaces / HID collections) go phantom even though the target node itself
    // can still report OK. A plain "is it enabled?" check wrongly succeeds here, so
    // we must restart the target to make its children re-attach.
    if (target.method == "removed" || target.method == "ejected") {
      DEVINST devinst = 0;
      if (CM_Locate_DevNodeW(&devinst, wide.data(), CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS) {
        CM_Reenumerate_DevNode(devinst, CM_REENUMERATE_SYNCHRONOUS);
      }
      if (!target.parent_id.empty()) {
        std::wstring wide_parent(target.parent_id.begin(), target.parent_id.end());
        DEVINST parent = 0;
        if (CM_Locate_DevNodeW(&parent, wide_parent.data(), CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS) {
          CM_Reenumerate_DevNode(parent, CM_REENUMERATE_SYNCHRONOUS);
        }
      }
      if (!target.hub_id.empty() && target.port != 0) {
        cycle_port(target.hub_id, target.port);
      }
      // Global rescan ("Scan for hardware changes") re-creates phantom children.
      rescan_devices();
      return true;
    }

    // disabled/legacy: restore in place, then re-enumerate the parent as a fallback.
    DEVINST devinst = 0;
    if (CM_Locate_DevNodeW(&devinst, wide.data(), CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS) {
      if (restore_node(devinst, false)) {
        return true;
      }
    }
    if (!target.parent_id.empty()) {
      std::wstring wide_parent(target.parent_id.begin(), target.parent_id.end());
      DEVINST parent = 0;
      if (CM_Locate_DevNodeW(&parent, wide_parent.data(), CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS) {
        CM_Reenumerate_DevNode(parent, CM_REENUMERATE_SYNCHRONOUS);
        return true;
      }
    }

    return false;
  }

  /**
   * @brief Block a device node by ejecting/removing it.
   * @details Eject/remove ONLY: CM_Query_And_Remove_SubTree (problem code 21) then
   *          CM_Request_Device_Eject (problem code 47). We deliberately do NOT fall
   *          back to CM_Disable_DevNode / DICS_DISABLE / registry_disable: those
   *          write CONFIGFLAG_DISABLED, which is reboot-persistent and can be baked
   *          into a state snapshot (the 1.1.8 lockout). Eject/remove is cleared by a
   *          reboot and never touches the registry.
   * @return `removed`, `ejected`, `already_blocked`, or `error_<code>`.
   */
  std::string disable_node(DEVINST devinst, const std::string &name) {
    if (node_is_blocked(devinst)) {
      return "already_blocked";
    }

    return eject_node(devinst, name);
  }

  /**
   * @brief Outcome of trying to block one physical device.
   */
  struct block_outcome_t {
    std::string group_key;   ///< Topmost physical node (for dedup); empty when virtual.
    std::string target_id;   ///< Node actually targeted.
    std::string result;      ///< `disabled`, `removed`, `ejected`, `already_blocked`, `would_disable`, `not_disableable`, or `skipped_virtual`.
  };

  /**
   * @brief Block the physical device owning a HID collection.
   * @details Tries each node in the collection's physical HID/USB chain, from the
   *          topmost (USB composite) down to the collection, until one can be
   *          blocked. Virtual devices (no USB ancestor) are never touched.
   */
  block_outcome_t block_physical_device(DEVINST collection, bool dry_run) {
    const auto chain = build_physical_chain(collection);
    if (chain.empty()) {
      return {"", "", "skipped_virtual"};
    }

    const std::string group_key = device_instance_id(chain.back());

    for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
      const std::string id = device_instance_id(*it);
      if (dry_run) {
        return {group_key, id, node_is_blocked(*it) ? "already_blocked" : "would_disable"};
      }
      const std::string result = disable_node(*it, id);
      if (result == "disabled" || result == "removed" || result == "ejected" || result == "already_blocked") {
        blocked_target_t target;
        target.instance_id = id;
        target.method = result == "already_blocked" ? block_method(*it) : result;
        target.parent_id = parent_instance_id(*it);
        // Record the hub + port so restore can do a "software replug" even if the
        // device node is already gone.
        find_hub_and_port(*it, target.hub_id, target.port);
        add_blocked_target(target);
        return {group_key, id, result};
      }
    }

    return {group_key, device_instance_id(chain.back()), "not_disableable"};
  }

  /**
   * @brief Enable or disable physical keyboard and mouse input.
   * @details Only devices with a physical HID/USB ancestor are touched, so virtual
   *          HID devices (FakerInput, Sunshine's own input) are never disabled.
   *          The active HID keyboard collection is not disableable, so we disable
   *          the highest disableable node in its HID/USB chain.
   * @param enable True to enable (unblock/self-heal), false to disable (block).
   * @param dry_run True to plan only (report what would change, make no changes).
   * @return JSON array describing the outcome for each device.
   */
  nlohmann::json apply_input_state(bool enable, bool dry_run) {
    nlohmann::json results = nlohmann::json::array();
    std::map<std::string, std::string> target_result;

    auto apply_class = [&](const GUID &class_guid) {
      for (const auto &device : enumerate_input_class(class_guid)) {
        nlohmann::json entry;
        entry["name"] = device.name;
        entry["instance_id"] = device.instance_id;

        if (!enable) {
          const auto outcome = block_physical_device(device.devinst, dry_run);
          if (outcome.result == "skipped_virtual") {
            entry["result"] = "skipped_virtual";
            results.push_back(std::move(entry));
            continue;
          }

          entry["target"] = outcome.target_id;

          auto known = target_result.find(outcome.group_key);
          if (known != target_result.end()) {
            entry["result"] = "duplicate";
            entry["first_result"] = known->second;
            results.push_back(std::move(entry));
            continue;
          }

          target_result.emplace(outcome.group_key, outcome.result);
          entry["result"] = outcome.result;
        } else if (dry_run) {
          entry["result"] = device.disabled ? "would_enable" : "already_enabled";
        } else {
          entry["result"] = enable_device(device);
        }

        results.push_back(std::move(entry));
      }
    };

    apply_class(class_guid_keyboard);
    apply_class(class_guid_mouse);

    if (enable) {
      // Disabled parents/HID devices hide their child collections, so re-enable any
      // disabled HID/USB input nodes still present on the bus.
      for (const auto &device : enumerate_disabled_hid_bus_nodes()) {
        nlohmann::json entry;
        entry["name"] = device.name;
        entry["instance_id"] = device.instance_id;
        if (dry_run) {
          entry["result"] = device.disabled ? "would_enable" : "already_enabled";
        } else {
          entry["result"] = enable_device(device);
        }
        results.push_back(std::move(entry));
      }

      // Full cascade heal over ALL USB/HID nodes — catches hidden/unrecorded devices
      // and the "enabling a parent reveals more disabled children" wave.
      if (!dry_run) {
        nlohmann::json entry;
        entry["name"] = "cascade-heal";
        entry["instance_id"] = "cascade-heal";
        entry["result"] = "enabled";
        entry["passes"] = heal_input_devices(15);
        results.push_back(std::move(entry));
      }

      // Restore recorded targets; KEEP any that failed so the next boot retries.
      std::vector<blocked_target_t> remaining;
      for (const auto &target : read_blocked_targets()) {
        nlohmann::json entry;
        entry["name"] = target.instance_id;
        entry["instance_id"] = target.instance_id;
        entry["method"] = target.method;
        if (dry_run) {
          entry["result"] = "would_enable";
        } else {
          const bool ok = restore_target(target);
          entry["result"] = ok ? "enabled" : "error_enable";
          if (!ok) {
            remaining.push_back(target);
          }
        }
        results.push_back(std::move(entry));
      }

      if (!dry_run) {
        write_blocked_targets(remaining);
      }
    }

    return results;
  }

  /**
   * @brief Count entries in a device result list that match a given result string.
   * @param results Result list produced by @ref apply_input_state.
   * @param wanted Result string to match.
   * @return Number of matching entries.
   */
  int count_results(const nlohmann::json &results, const std::string &wanted) {
    int count = 0;
    for (const auto &entry : results) {
      if (entry.value("result", std::string {}) == wanted) {
        ++count;
      }
    }
    return count;
  }

  /**
   * @brief Turn the physical display(s) on or off.
   * @details Sends the standard `SC_MONITORPOWER` system command on the input desktop.
   *          The GPU keeps rendering, so screen capture is unaffected by display standby.
   * @param off True to power the display off (standby), false to power it on.
   * @return True when the command was delivered to the desktop.
   */
  bool set_monitor_power(bool off) {
    platf::syncThreadDesktop();

    DWORD_PTR result = 0;
    auto parameter = static_cast<LPARAM>(off ? 2 : -1);
    auto delivered = SendMessageTimeoutW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, parameter, SMTO_ABORTIFHUNG | SMTO_BLOCK, 2000, &result);
    return delivered != 0;
  }

  /**
   * @brief Subscribes to the OS display-state power settings and tracks the latest value.
   * @details Registers GUID_CONSOLE_DISPLAY_STATE + GUID_MONITOR_POWER_ON on a dedicated
   *          thread that pumps its message queue (that's where the notification callback
   *          is delivered). Create it BEFORE toggling the display so no transition is
   *          missed. Reports the OS display-stack state (0 = off, 1 = on, 2 = dimmed).
   */
  class display_watch_t {
  public:
    display_watch_t() {
      static const GUID guid_console_display_state = {0x6FE69556, 0x704A, 0x47A0, {0x8F, 0x24, 0xC2, 0x8D, 0x93, 0x6F, 0xDA, 0x47}};
      static const GUID guid_monitor_power_on = {0x02731015, 0x4510, 0x4526, {0x99, 0xE6, 0xE5, 0xA1, 0x7E, 0xBD, 0x1A, 0xEA}};
      constexpr DWORD device_notify_callback = 2;

      powrprof_ = LoadLibraryExW(L"powrprof.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
      if (!powrprof_) {
        return;
      }
      reg_ = reinterpret_cast<register_fn_t>(GetProcAddress(powrprof_, "PowerSettingRegisterNotification"));
      unreg_ = reinterpret_cast<unregister_fn_t>(GetProcAddress(powrprof_, "PowerSettingUnregisterNotification"));
      if (!reg_ || !unreg_) {
        FreeLibrary(powrprof_);
        powrprof_ = nullptr;
        return;
      }

      subscribe_t params {};
      params.Callback = [](PVOID context, ULONG, PVOID setting) -> ULONG {
        auto *s = static_cast<power_setting_t *>(setting);
        auto *state = static_cast<std::atomic<int> *>(context);
        if (s && s->DataLength >= sizeof(DWORD)) {
          state->store(static_cast<int>(*reinterpret_cast<DWORD *>(s->Data)));
        }
        return ERROR_SUCCESS;
      };
      params.Context = &state_;

      thread_ = std::thread([this, params]() {
        HANDLE h_console = nullptr;
        HANDLE h_monitor = nullptr;
        if (reg_(&guid_console_display_state, device_notify_callback, &params, &h_console) != ERROR_SUCCESS) {
          h_console = nullptr;
        }
        if (reg_(&guid_monitor_power_on, device_notify_callback, &params, &h_monitor) != ERROR_SUCCESS) {
          h_monitor = nullptr;
        }

        while (!stop_.load()) {
          MSG msg;
          MsgWaitForMultipleObjects(0, nullptr, FALSE, 50, QS_ALLINPUT);
          while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
          }
        }

        if (h_console) {
          unreg_(h_console);
        }
        if (h_monitor) {
          unreg_(h_monitor);
        }
      });
    }

    ~display_watch_t() {
      stop_.store(true);
      if (thread_.joinable()) {
        thread_.join();
      }
      if (powrprof_) {
        FreeLibrary(powrprof_);
      }
    }

    /** @brief Latest observed display state (-1 = unknown / not yet reported). */
    int state() const {
      return state_.load();
    }

    /**
     * @brief Wait for the display to settle ON (value 1).
     * @details Waits up to @p max_wait; if the probe never reports anything it gives
     *          up after @p probe_grace (the API itself is unavailable). Gating on the
     *          exact value 1 avoids latching a transitional/dim value (2).
     */
    bool wait_for_on(std::chrono::milliseconds max_wait, std::chrono::milliseconds probe_grace) {
      const auto start = std::chrono::steady_clock::now();
      bool probe_seen = false;
      while (std::chrono::steady_clock::now() - start < max_wait) {
        const int current = state_.load();
        if (current == 1) {
          return true;
        }
        if (current >= 0) {
          probe_seen = true;
        }
        if (!probe_seen && std::chrono::steady_clock::now() - start >= probe_grace) {
          break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
      return state_.load() == 1;
    }

  private:
    using register_fn_t = DWORD(WINAPI *)(const GUID *, DWORD, PVOID, HANDLE *);
    using unregister_fn_t = DWORD(WINAPI *)(HANDLE);

    struct power_setting_t {
      GUID PowerSetting;
      DWORD DataLength;
      UCHAR Data[1];
    };
    struct subscribe_t {
      ULONG(WINAPI *Callback)(PVOID, ULONG, PVOID);
      PVOID Context;
    };

    HMODULE powrprof_ = nullptr;
    register_fn_t reg_ = nullptr;
    unregister_fn_t unreg_ = nullptr;
    std::atomic<int> state_ {-1};
    std::atomic<bool> stop_ {false};
    std::thread thread_;
  };

  /**
   * @brief Wake the physical display(s): ES_DISPLAY_REQUIRED, then imitated input.
   * @details Subscribes to the display-state notification BEFORE toggling (so no
   *          transition is missed), toggles, then waits for the state to settle ON.
   *          Only when it does not settle ON do we inject a synthetic mouse move.
   * @return True when a wake method reported success.
   */
  bool wake_display() {
    platf::syncThreadDesktop();

    display_watch_t watch;

    SetThreadExecutionState(ES_CONTINUOUS | ES_DISPLAY_REQUIRED);
    set_monitor_power(false);

    // Wait up to 5s for a settled "on"; give up after 1.5s if the probe never reports.
    const bool settled_on = watch.wait_for_on(std::chrono::seconds(5), std::chrono::milliseconds(1500));
    SetThreadExecutionState(ES_CONTINUOUS);

    if (settled_on) {
      BOOST_LOG(info) << "Monitor on: woke via ES_DISPLAY_REQUIRED (display state=on)"sv;
      return true;
    }

    // Idempotent nudge: 1px and back (net-zero cursor) to wake DPMS.
    INPUT inputs[2] {};
    inputs[0].type = INPUT_MOUSE;
    inputs[0].mi.dx = 1;
    inputs[0].mi.dy = 0;
    inputs[0].mi.dwFlags = MOUSEEVENTF_MOVE;
    inputs[1].type = INPUT_MOUSE;
    inputs[1].mi.dx = -1;
    inputs[1].mi.dy = 0;
    inputs[1].mi.dwFlags = MOUSEEVENTF_MOVE;
    const UINT sent = SendInput(2, inputs, sizeof(INPUT));

    BOOST_LOG(info) << "Monitor on: ES_DISPLAY_REQUIRED did not settle on (last display state="sv << watch.state() << ") -> woke via synthetic input (sent="sv << sent << ")"sv;
    return sent == 2;
  }

  /**
   * @brief Keep the physical display in standby while remote input keeps waking it.
   * @details Re-asserts the power-off command every 20 seconds until @ref monitor_off_active is cleared.
   */
  void monitor_off_keepalive() {
    while (monitor_off_active.load()) {
      for (int tick = 0; tick < 20 && monitor_off_active.load(); ++tick) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }
      if (monitor_off_active.load()) {
        set_monitor_power(true);
      }
    }
  }

  /** @brief True while a physical-input block is active (watchdog keeps re-applying). */
  std::atomic<bool> input_block_active {false};
  /** @brief Guards block/unblock/self-heal and the watchdog. */
  std::mutex input_block_mutex;
  /** @brief Guards the watchdog thread handle. */
  std::mutex input_block_watchdog_mutex;
  /** @brief Background thread that re-blocks newly plugged physical input. */
  std::jthread input_block_watchdog;

  /** @brief Set by the CM notification callback when a device interface arrives. */
  std::atomic<bool> input_block_arrival_pending {false};

  /**
   * @brief CM device-interface arrival callback (delivered on the watchdog thread).
   */
  DWORD CALLBACK input_block_notify_callback(HCMNOTIFICATION, PVOID context, CM_NOTIFY_ACTION action, PCM_NOTIFY_EVENT_DATA, DWORD) {
    if (action == CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL) {
      static_cast<std::atomic<bool> *>(context)->store(true);
    }
    return ERROR_SUCCESS;
  }

  /** @brief Re-apply the block after an arrival event and log what it caught. */
  void input_block_reapply_after_event() {
    std::lock_guard<std::mutex> lock(input_block_mutex);
    if (!input_block_active.load()) {
      return;
    }
    const auto results = apply_input_state(false, false);
    int blocked = 0;
    for (const auto &entry : results) {
      const auto r = entry.value("result", std::string {});
      if (r == "disabled" || r == "removed" || r == "ejected") {
        ++blocked;
      }
    }
    BOOST_LOG(info) << "Input block: re-blocked "sv << blocked << " device(s) after arrival event"sv;
  }

  /** @brief 5s poll fallback used when event notifications are unavailable. */
  void input_block_poll_loop(std::stop_token stop_token) {
    using namespace std::chrono_literals;
    while (!stop_token.stop_requested()) {
      for (int tick = 0; tick < 50 && !stop_token.stop_requested(); ++tick) {
        std::this_thread::sleep_for(100ms);
      }
      if (stop_token.stop_requested()) {
        break;
      }
      std::lock_guard<std::mutex> lock(input_block_mutex);
      if (!input_block_active.load()) {
        break;
      }
      apply_input_state(false, false);
    }
  }

  /**
   * @brief Re-apply the block on device-arrival notifications, with a poll fallback.
   * @details Registers CM notifications for HID and USB device interfaces and pumps
   *          the thread message queue (required for delivery). On arrival it
   *          debounces briefly, then re-applies the block. Falls back to a 5s poll
   *          when registration is unavailable.
   */
  void input_block_watchdog_loop(std::stop_token stop_token) {
    using namespace std::chrono_literals;

    constexpr GUID guid_devinterface_hid = {0x4D1E55B2, 0xF16F, 0x11CF, {0x88, 0xCB, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30}};
    constexpr GUID guid_devinterface_usb_device = {0xA5DCBF10, 0x6530, 0x11D2, {0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED}};

    CM_NOTIFY_FILTER filters[2] = {};
    filters[0].cbSize = sizeof(CM_NOTIFY_FILTER);
    filters[0].FilterType = CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE;
    filters[0].u.DeviceInterface.ClassGuid = guid_devinterface_hid;
    filters[1] = filters[0];
    filters[1].u.DeviceInterface.ClassGuid = guid_devinterface_usb_device;

    HCMNOTIFICATION handles[2] = {};
    int registered = 0;
    for (int i = 0; i < 2; ++i) {
      if (CM_Register_Notification(&filters[i], &input_block_arrival_pending, &input_block_notify_callback, &handles[i]) == CR_SUCCESS) {
        ++registered;
      }
    }

    if (registered == 0) {
      BOOST_LOG(warning) << "Input block: event watchdog unavailable -> using 5s poll fallback"sv;
      input_block_poll_loop(stop_token);
      return;
    }

    BOOST_LOG(info) << "Input block: event watchdog active (device-arrival notifications)"sv;

    while (!stop_token.stop_requested()) {
      // Pump the message queue so CM can deliver notifications.
      MSG msg;
      MsgWaitForMultipleObjects(0, nullptr, FALSE, 200, QS_ALLINPUT);
      while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
      }

      if (input_block_arrival_pending.exchange(false)) {
        // Debounce: let the device finish arriving before we act.
        for (int tick = 0; tick < 10 && !stop_token.stop_requested(); ++tick) {
          std::this_thread::sleep_for(100ms);
        }
        if (stop_token.stop_requested()) {
          break;
        }
        input_block_reapply_after_event();
        if (!input_block_active.load()) {
          break;
        }
      }
    }

    for (int i = 0; i < 2; ++i) {
      if (handles[i]) {
        CM_Unregister_Notification(handles[i]);
      }
    }
  }

  /**
   * @brief Stop the input-block watchdog (idempotent).
   */
  void stop_input_block_watchdog() {
    std::lock_guard<std::mutex> lock(input_block_watchdog_mutex);
    input_block_active.store(false);
    if (input_block_watchdog.joinable()) {
      input_block_watchdog.request_stop();
      input_block_watchdog.join();
    }
  }

  /**
   * @brief Start the input-block watchdog.
   */
  void start_input_block_watchdog() {
    if (!config::input.input_block_watchdog) {
      BOOST_LOG(info) << "Input block: watchdog disabled by configuration"sv;
      return;
    }
    std::lock_guard<std::mutex> lock(input_block_watchdog_mutex);
    input_block_active.store(true);
    input_block_arrival_pending.store(false);
    input_block_watchdog = std::jthread(input_block_watchdog_loop);
  }

  /**
   * @brief Re-enable any physical input disabled by a previous session (startup self-heal).
   */
  void self_heal_input_state() {
    // Run on a background thread so a slow/blocked device tree can never stop
    // Sunshine from starting. Give the device tree (and any state-revert) time to
    // settle before healing.
    std::thread([]() {
      std::this_thread::sleep_for(std::chrono::seconds(5));
      {
        std::lock_guard<std::mutex> lock(input_block_mutex);
        input_block_verbose.store(true);
        apply_input_state(true, false);
        input_block_verbose.store(false);
      }
      BOOST_LOG(info) << "Input block: startup self-heal complete"sv;
    }).detach();
  }

  /**
   * @brief Restore all physical input devices and the display (used on graceful shutdown).
   */
  void restore_input_state() {
    stop_input_block_watchdog();
    monitor_off_active.store(false);
    wake_display();
    {
      std::lock_guard<std::mutex> lock(input_block_mutex);
      apply_input_state(true, false);
    }
    BOOST_LOG(info) << "Input block: restored keyboard, mouse and display state"sv;
  }
#endif

  /**
   * @brief Get input block configuration and status.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/input-block/status| GET| null}
   */
  void getInputBlockStatus(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    print_req(request);

    nlohmann::json output_tree;

#ifdef _WIN32
    auto keyboards = enumerate_input_class(class_guid_keyboard);
    auto mice = enumerate_input_class(class_guid_mouse);
    auto monitors = enumerate_input_class(class_guid_monitor);
    auto all_devices = enumerate_usb_hid_devices();

    // Visible (class-based) disabled state.
    bool blocked = false;
    for (const auto &device : keyboards) {
      blocked = blocked || device.disabled;
    }
    for (const auto &device : mice) {
      blocked = blocked || device.disabled;
    }

    // Authoritative blocked state: any USB/HID node with a block problem code,
    // including devices hidden behind a disabled parent (the class scan can't see them).
    std::vector<std::string> visible_ids;
    for (const auto &device : keyboards) {
      visible_ids.push_back(device.instance_id);
    }
    for (const auto &device : mice) {
      visible_ids.push_back(device.instance_id);
    }

    nlohmann::json blocked_nodes = nlohmann::json::array();
    nlohmann::json hidden_blocked = nlohmann::json::array();
    nlohmann::json devices_json = nlohmann::json::array();
    for (const auto &device : all_devices) {
      devices_json.push_back(device_info_to_json(device));
      if (is_block_problem(device.problem)) {
        blocked = true;
        blocked_nodes.push_back(device_info_to_json(device));
        if (std::find(visible_ids.begin(), visible_ids.end(), device.instance_id) == visible_ids.end()) {
          hidden_blocked.push_back(device_info_to_json(device));
        }
      }
    }

    nlohmann::json recorded = nlohmann::json::array();
    for (const auto &target : read_blocked_targets()) {
      recorded.push_back({{"instance_id", target.instance_id}, {"method", target.method}, {"parent", target.parent_id}});
    }

    output_tree["configured"] = true;
    output_tree["method"] = "native";
    output_tree["enabled"] = config::input.input_block_enabled;
    output_tree["blocked"] = blocked;
    output_tree["blocked_count"] = blocked_nodes.size();
    output_tree["hidden_blocked_count"] = hidden_blocked.size();
    output_tree["monitor_off"] = monitor_off_active.load();
    output_tree["keyboard"] = devices_to_json(keyboards);
    output_tree["mouse"] = devices_to_json(mice);
    output_tree["monitor"] = devices_to_json(monitors);
    output_tree["keyboard_count"] = keyboards.size();
    output_tree["mouse_count"] = mice.size();
    output_tree["monitor_count"] = monitors.size();
    output_tree["blocked_nodes"] = blocked_nodes;
    output_tree["hidden_blocked"] = hidden_blocked;
    output_tree["devices"] = devices_json;
    output_tree["recorded_targets"] = recorded;
#else
    output_tree["configured"] = false;
    output_tree["error"] = "Input blocking is only available on Windows";
#endif

    send_response(response, output_tree);
  }

  /**
   * @brief Block physical keyboard and mouse input.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/input-block/block| POST| null}
   */
  void blockInput(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    nlohmann::json output_tree;

#ifdef _WIN32
    if (!config::input.input_block_enabled) {
      output_tree["status"] = false;
      output_tree["error"] = "Input block is disabled by configuration (set input_block_enabled=true)";
      send_response(response, output_tree);
      return;
    }

    const bool dry_run = request_dry_run(request);

    nlohmann::json results;
    if (dry_run) {
      std::lock_guard<std::mutex> lock(input_block_mutex);
      results = apply_input_state(false, true);
    } else {
      stop_input_block_watchdog();
      input_block_verbose.store(true);
      {
        std::lock_guard<std::mutex> lock(input_block_mutex);
        results = apply_input_state(false, false);
      }
      input_block_verbose.store(false);
    }

    const int disabled_count = count_results(results, "disabled") + count_results(results, "removed") + count_results(results, "ejected");
    const int would_count = count_results(results, "would_disable");
    const int already_blocked_count = count_results(results, "already_blocked") + count_results(results, "already_disabled");
    const int skipped_count = count_results(results, "skipped_virtual");
    const int duplicate_count = count_results(results, "duplicate");

    output_tree["status"] = true;
    output_tree["dry_run"] = dry_run;
    output_tree["blocked"] = dry_run ? (would_count + already_blocked_count) > 0 : disabled_count > 0;
    output_tree["blocked_count"] = dry_run ? would_count : disabled_count;
    output_tree["skipped_virtual_count"] = skipped_count;
    output_tree["duplicate_count"] = duplicate_count;
    output_tree["devices"] = results;

    if (!dry_run && (disabled_count > 0 || already_blocked_count > 0)) {
      // Watchdog re-applies the block to catch newly plugged physical devices.
      // Only start it when something is actually blocked (avoids retry/log spam).
      start_input_block_watchdog();
    }

    BOOST_LOG(info) << (dry_run ? "Input block (dry-run)"sv : "Input block"sv)
                    << ": physical keyboards and mice "sv << (dry_run ? "would be disabled"sv : "disabled"sv)
                    << " ("sv << output_tree["blocked_count"].get<int>() << " devices, "sv << skipped_count << " virtual skipped)"sv;
#else
    output_tree["status"] = false;
    output_tree["error"] = "Input blocking is only available on Windows";
#endif

    send_response(response, output_tree);
  }

  /**
   * @brief Unblock physical keyboard and mouse input.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/input-block/unblock| POST| null}
   */
  void unblockInput(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    nlohmann::json output_tree;

#ifdef _WIN32
    const bool dry_run = request_dry_run(request);

    nlohmann::json results;
    if (dry_run) {
      std::lock_guard<std::mutex> lock(input_block_mutex);
      results = apply_input_state(true, true);
    } else {
      stop_input_block_watchdog();
      input_block_verbose.store(true);
      {
        std::lock_guard<std::mutex> lock(input_block_mutex);
        results = apply_input_state(true, false);
      }
      input_block_verbose.store(false);
    }

    const int enabled_count = count_results(results, "enabled");
    const int would_count = count_results(results, "would_enable");
    const int already_count = count_results(results, "already_enabled");

    output_tree["status"] = true;
    output_tree["dry_run"] = dry_run;
    output_tree["blocked"] = dry_run ? would_count > 0 : false;
    output_tree["unblocked_count"] = dry_run ? would_count : enabled_count;
    output_tree["already_enabled_count"] = already_count;
    output_tree["devices"] = results;

    BOOST_LOG(info) << (dry_run ? "Input unblock (dry-run)"sv : "Input unblock"sv)
                    << ": physical keyboards and mice "sv << (dry_run ? "would be enabled"sv : "enabled"sv)
                    << " ("sv << output_tree["unblocked_count"].get<int>() << " devices)"sv;
#else
    output_tree["status"] = false;
    output_tree["error"] = "Input blocking is only available on Windows";
#endif

    send_response(response, output_tree);
  }

  /**
   * @brief Force a full cascade heal of all blocked USB/HID devices.
   * @details One-shot recovery that heals any device with problem 22/21/47 by full
   *          enumeration (present + hidden), independent of recorded targets.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/input-block/recover| POST| null}
   */
  void recoverInput(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    nlohmann::json output_tree;

#ifdef _WIN32
    stop_input_block_watchdog();
    input_block_verbose.store(true);
    nlohmann::json results;
    {
      std::lock_guard<std::mutex> lock(input_block_mutex);
      // Ultimate fix: cascade-heal every present blocked device AND restore recorded
      // targets (including removed/phantom ones, via their recorded parent).
      results = apply_input_state(true, false);
    }
    input_block_verbose.store(false);

    output_tree["status"] = true;
    output_tree["devices"] = results;

    BOOST_LOG(info) << "Input recover: full heal + record restore complete"sv;
#else
    output_tree["status"] = false;
    output_tree["error"] = "Input recovery is only available on Windows";
#endif

    send_response(response, output_tree);
  }

  /**
   * @brief Turn the physical display(s) off (standby).
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/input-block/monitor/off| POST| null}
   */
  void monitorOff(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    nlohmann::json output_tree;

#ifdef _WIN32
    const bool delivered = set_monitor_power(true);
    if (delivered && !monitor_off_active.exchange(true)) {
      std::thread(monitor_off_keepalive).detach();
    }

    output_tree["status"] = delivered;
    output_tree["monitor_off"] = monitor_off_active.load();
    if (!delivered) {
      output_tree["error"] = "Failed to deliver display power command";
    }
#else
    output_tree["status"] = false;
    output_tree["error"] = "Monitor control is only available on Windows";
#endif

    send_response(response, output_tree);
  }

  /**
   * @brief Turn the physical display(s) back on.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/input-block/monitor/on| POST| null}
   */
  void monitorOn(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    nlohmann::json output_tree;

#ifdef _WIN32
    monitor_off_active.store(false);
    const bool delivered = wake_display();

    output_tree["status"] = delivered;
    output_tree["monitor_off"] = false;
    if (!delivered) {
      output_tree["error"] = "Failed to wake display";
    }
#else
    output_tree["status"] = false;
    output_tree["error"] = "Monitor control is only available on Windows";
#endif

    send_response(response, output_tree);
  }

  /**
   * @brief Checks whether a directory entry qualifies as an executable file.
   * @param entry The directory entry to check.
   * @param status The cached file status for the entry.
   * @return True if the file should be included in an executable-type listing.
   */
  bool is_browsable_executable([[maybe_unused]] const fs::directory_entry &entry, [[maybe_unused]] const fs::file_status &status) {
#ifdef _WIN32
    auto ext = entry.path().extension().string();
    boost::algorithm::to_lower(ext);
    return ext == ".exe" || ext == ".bat" || ext == ".cmd" || ext == ".com" || ext == ".ps1";
#else
    const auto perms = status.permissions();
    return (perms & fs::perms::owner_exec) != fs::perms::none ||
           (perms & fs::perms::group_exec) != fs::perms::none ||
           (perms & fs::perms::others_exec) != fs::perms::none;
#endif
  }

#ifdef _WIN32
  /**
   * @brief Builds a JSON array of available Windows drive letters.
   * @return JSON array of drive-letter entries.
   */
  nlohmann::json get_windows_drives() {
    nlohmann::json entries = nlohmann::json::array();
    const DWORD drives = GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
      if (drives & (1 << i)) {
        const auto drive_letter = static_cast<char>('A' + i);
        const auto drive_path = std::string(1, drive_letter) + ":\\";
        nlohmann::json entry;
        entry["name"] = drive_path;
        entry["type"] = "directory";
        entry["path"] = drive_path;
        entries.push_back(entry);
      }
    }
    return entries;
  }
#endif

  /**
   * @brief Lists, filters, and sorts the entries of a directory for the browse API.
   * @param dir_path The directory to list.
   * @param type_str Filter type: "directory", "executable", "file", or "any".
   * @return Sorted JSON array of entry objects with name/type/path fields.
   */
  nlohmann::json build_browse_entries(const fs::path &dir_path, const std::string &type_str) {
    nlohmann::json entries = nlohmann::json::array();

    std::error_code iter_ec;
    for (auto it = fs::directory_iterator(dir_path, fs::directory_options::skip_permission_denied, iter_ec);
         !iter_ec && it != fs::directory_iterator();
         it.increment(iter_ec)) {
      try {
        const auto status = it->status();
        const bool is_dir = fs::is_directory(status);

        if (const bool is_regular = fs::is_regular_file(status); !is_dir && !is_regular) {
          continue;
        }

        // Apply type filter (directories are always included for navigation)
        if (type_str == "directory" && !is_dir) {
          continue;
        }

        if (type_str == "executable" && !is_dir && !is_browsable_executable(*it, status)) {
          continue;
        }

        nlohmann::json file_entry;
        file_entry["name"] = it->path().filename().string();
        file_entry["path"] = it->path().string();
        file_entry["type"] = is_dir ? "directory" : "file";
        entries.push_back(file_entry);
      } catch (const fs::filesystem_error &e) {
        BOOST_LOG(debug) << "BrowseDirectory: skipping entry due to error: "sv << e.what();
      }
    }

    if (iter_ec) {
      BOOST_LOG(debug) << "BrowseDirectory: directory iteration error: "sv << iter_ec.message();
    }

    // Sort: directories first, then files; both case-insensitively alphabetical
    std::sort(entries.begin(), entries.end(), [](const nlohmann::json &a, const nlohmann::json &b) {
      const bool a_dir = (a["type"] == "directory");
      if (const bool b_dir = (b["type"] == "directory"); a_dir != b_dir) {
        return a_dir && !b_dir;
      }
      auto a_name = a["name"].get<std::string>();
      auto b_name = b["name"].get<std::string>();
      boost::algorithm::to_lower(a_name);
      boost::algorithm::to_lower(b_name);
      return a_name < b_name;
    });

    return entries;
  }

  /**
   * @brief Browse the server filesystem.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   * @note On Windows, an empty or root path returns the list of available drive letters.
   * @note On non-Windows, an empty path defaults to the filesystem root ("/").
   *
   * @api_examples{/api/browse?path=/home/user&type=directory| GET| null}
   */
  void browseDirectory(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    print_req(request);

    try {
      const auto query_params = request->parse_query_string();

      std::string path_str;
      if (const auto path_it = query_params.find("path"); path_it != query_params.end()) {
        path_str = path_it->second;
      }

      std::string type_str = "any";
      if (const auto type_it = query_params.find("type"); type_it != query_params.end() && !type_it->second.empty()) {
        type_str = type_it->second;
      }

      nlohmann::json output_tree;

#ifdef _WIN32
      // On Windows with an empty or root path, return the list of available drive letters
      if (path_str.empty() || path_str == "/" || path_str == "\\") {
        output_tree["path"] = "";
        output_tree["parent"] = "";
        output_tree["entries"] = get_windows_drives();
        send_response(response, output_tree);
        return;
      }
#else
      // On non-Windows, default an empty path to the filesystem root
      if (path_str.empty()) {
        path_str = "/";
      }
#endif

      // Normalize the path
      fs::path dir_path = fs::weakly_canonical(fs::path(path_str));

      // If the path points to a file, use its parent directory
      std::error_code ec;
      if (fs::is_regular_file(dir_path, ec)) {
        dir_path = dir_path.parent_path();
      }

      // If the path doesn't exist, try the parent
      if (!fs::exists(dir_path, ec)) {
        dir_path = dir_path.parent_path();
      }

      if (!fs::is_directory(dir_path, ec)) {
        bad_request(response, request, "Path is not a directory");
        return;
      }

      output_tree["path"] = dir_path.string();

      // Determine the parent path for the "Up" navigation
      const fs::path parent = dir_path.parent_path();
#ifdef _WIN32
      // At a drive root (e.g., C:\) the parent equals itself; signal the drive list with an empty string
      output_tree["parent"] = (parent == dir_path) ? "" : parent.string();
#else
      output_tree["parent"] = parent.string();
#endif

      output_tree["entries"] = build_browse_entries(dir_path, type_str);
      send_response(response, output_tree);
    } catch (const fs::filesystem_error &e) {
      BOOST_LOG(warning) << "BrowseDirectory: "sv << e.what();
      bad_request(response, request, e.what());
    }
  }

  // --- Upgrade API ---
  namespace {
    std::atomic<bool> upgrade_in_progress {false};
    std::mutex upgrade_mutex;
    std::string upgrade_last_error;
    std::string upgrade_latest_version;
    const std::string upgrade_current_version = PROJECT_VERSION_COMMIT;

    std::atomic<bool> netbird_update_in_progress {false};
    std::string netbird_update_error;

    size_t curl_write_string_callback(void *contents, size_t size, size_t nmemb, void *userp) {
      size_t totalSize = size * nmemb;
      std::string *str = static_cast<std::string *>(userp);
      str->append(static_cast<char *>(contents), totalSize);
      return totalSize;
    }

    std::string fetch_url(const std::string &url, long timeout_sec = 30) {
      CURL *curl = curl_easy_init();
      if (!curl) {
        BOOST_LOG(error) << "Failed to create CURL instance for URL fetch";
        return "";
      }

      std::string result;
      curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_string_callback);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);
      curl_easy_setopt(curl, CURLOPT_USERAGENT, "LegionGames-Sunshine-Updater/1.0");
      curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
      curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_sec);
      curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);

      CURLcode res = curl_easy_perform(curl);
      if (res != CURLE_OK) {
        BOOST_LOG(error) << "Failed to fetch URL ["sv << url << "]: "sv << curl_easy_strerror(res);
      }

      curl_easy_cleanup(curl);
      return (res == CURLE_OK) ? result : "";
    }

#ifdef _WIN32
    /** @brief Appdata path of the persisted upgrade state. */
    std::filesystem::path upgrade_state_path() {
      return std::filesystem::path(platf::appdata()) / "upgrade_state.json";
    }

    /** @brief Read the persisted upgrade state (empty object when absent). */
    nlohmann::json read_upgrade_state() {
      try {
        const std::string content = file_handler::read_file(upgrade_state_path().string().c_str());
        if (!content.empty()) {
          return nlohmann::json::parse(content);
        }
      } catch (...) {}
      return nlohmann::json::object();
    }

    /** @brief Persist the upgrade state. */
    void write_upgrade_state(const nlohmann::json &state) {
      file_handler::write_file(upgrade_state_path().string().c_str(), state.dump(2));
    }

    /**
     * @brief Run a command synchronously and return its exit code (-1 on launch error).
     */
    int run_and_wait(const std::string &cmd, const boost::filesystem::path &working_dir) {
      std::error_code ec;
      boost::filesystem::path wd = working_dir;
      boost::process::v1::environment env = boost::this_process::environment();
      // Elevated: the install lives under Program Files, so the backup (robocopy)
      // and the scheduled-task registration both need administrator rights.
      auto child = platf::run_command(true, false, cmd, wd, env, nullptr, ec, nullptr);
      if (ec || !child.valid()) {
        return -1;
      }
      child.wait(ec);
      return ec ? -1 : child.exit_code();
    }

    /**
     * @brief Back up the current install and arm the update health supervisor.
     * @details Copies program files (excluding `config/` and `rollback/`) to
     *          `<install>/rollback/<from_commit>/`, writes `upgrade_state.json`, and
     *          registers + starts the one-shot `SunshineUpdateVerify` task that runs
     *          `scripts/update-supervisor.ps1`. That supervisor polls `/api/health`
     *          after the install and rolls back to @p from_commit if the new build
     *          never comes online. Best effort: returns false (update still proceeds)
     *          when the backup or task registration fails.
     */
    bool arm_update_supervisor(const std::string &from_commit, const std::string &to_commit) {
      wchar_t exe_path[MAX_PATH] {};
      if (GetModuleFileNameW(nullptr, exe_path, ARRAYSIZE(exe_path)) == 0) {
        BOOST_LOG(warning) << "Upgrade: cannot resolve install directory for rollback"sv;
        return false;
      }

      const std::filesystem::path install_dir = std::filesystem::path(exe_path).parent_path();
      const std::filesystem::path config_dir = install_dir / L"config";
      const std::filesystem::path rollback_root = install_dir / L"rollback";
      const std::filesystem::path backup_dir = rollback_root / std::wstring(from_commit.begin(), from_commit.end());
      const std::filesystem::path supervisor_script = install_dir / L"scripts" / L"update-supervisor.ps1";
      const std::filesystem::path config_script = config_dir / L"update-supervisor.ps1";
      const std::filesystem::path launcher = config_dir / L"update-supervisor-launch.cmd";
      const std::filesystem::path arm_log = config_dir / L"update-arm.log";

      // Persist arm progress to config/ (sunshine.log rotates on restart, losing it).
      auto log_arm = [&](const std::string &line) {
        std::ofstream out(arm_log, std::ios::app);
        if (out) {
          out << std::format("[{}] {}\n",
            static_cast<long long>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()), line);
        }
      };

      std::error_code ec;
      if (!std::filesystem::exists(supervisor_script, ec)) {
        BOOST_LOG(warning) << "Upgrade: update-supervisor.ps1 not present, skipping rollback supervision"sv;
        log_arm("supervisor script missing; skipped");
        return false;
      }

      // 1. Back up program files (exclude config and the rollback tree itself).
      std::filesystem::create_directories(backup_dir, ec);
      const std::string backup_cmd = std::format(
        "robocopy \"{}\" \"{}\" /E /XD \"{}\" \"{}\" /R:0 /W:0 /NFL /NDL /NJH /NJS /NP",
        install_dir.string(), backup_dir.string(), config_dir.string(), rollback_root.string());
      const int rc = run_and_wait(backup_cmd, boost::filesystem::path(install_dir.string()));
      log_arm(std::format("backup rc={}", rc));
      if (rc < 0 || (rc & 8) != 0) {
        BOOST_LOG(warning) << "Upgrade: rollback backup failed (robocopy "sv << rc << "), skipping rollback supervision"sv;
        return false;
      }
      BOOST_LOG(info) << "Upgrade: rollback backup created at "sv << backup_dir.string();

      // 2. Persist the state the supervisor reads.
      nlohmann::json state;
      state["phase"] = "preparing";
      state["from_commit"] = from_commit;
      state["to_commit"] = to_commit;
      state["install_dir"] = install_dir.string();
      state["backup_dir"] = backup_dir.string();
      state["port"] = static_cast<int>(net::map_port(PORT_HTTPS));
      state["started_at"] = static_cast<long long>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
      write_upgrade_state(state);

      // 3. Stage the supervisor into config/ so it survives the installer's
      //    uninstall-before-install (scripts/ is removed mid-update).
      std::filesystem::copy_file(supervisor_script, config_script, std::filesystem::copy_options::overwrite_existing, ec);
      if (ec) {
        log_arm(std::format("stage supervisor failed: {}", ec.message()));
        BOOST_LOG(warning) << "Upgrade: failed to stage supervisor script ("sv << ec.message() << ")"sv;
        return false;
      }

      // 4. Launcher: absolute PowerShell path, staged script, short delay so the
      //    install settles first. The task action runs it via cmd.exe.
      const std::string launcher_content = std::format(
        "@echo off\r\n"
        "ping -n 21 127.0.0.1 >nul\r\n"
        "\"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoProfile -ExecutionPolicy Bypass -File \"{}\" -StatePath \"{}\"\r\n",
        config_script.string(), upgrade_state_path().string());
      file_handler::write_file(launcher.string().c_str(), launcher_content);

      // 5. Register + start the one-shot task. The action goes through cmd.exe so
      //    Task Scheduler never has to launch a .cmd directly (that returned
      //    ERROR_FILE_NOT_FOUND, 0x80070002).
      const std::string create_cmd = std::format(
        "schtasks /Create /TN SunshineUpdateVerify /TR \"cmd.exe /c \\\"{}\\\"\" /SC ONSTART /RU SYSTEM /RL HIGHEST /F",
        launcher.string());
      const int create_rc = run_and_wait(create_cmd, boost::filesystem::path());
      log_arm(std::format("schtasks create rc={}", create_rc));
      if (create_rc != 0) {
        BOOST_LOG(warning) << "Upgrade: failed to register supervisor task ("sv << create_rc << ")"sv;
        return false;
      }
      const int run_rc = run_and_wait("schtasks /Run /TN SunshineUpdateVerify", boost::filesystem::path());
      log_arm(std::format("schtasks run rc={}", run_rc));
      if (run_rc != 0) {
        BOOST_LOG(warning) << "Upgrade: failed to start supervisor task ("sv << run_rc << ")"sv;
        return false;
      }

      BOOST_LOG(info) << "Upgrade: update supervisor armed (rollback to "sv << from_commit << ")"sv;
      log_arm("armed");
      return true;
    }
#endif

    void upgrade_background_task(bool force, bool rollback_on_failure) {
      upgrade_in_progress.store(true);
      {
        std::lock_guard<std::mutex> lock(upgrade_mutex);
        upgrade_last_error.clear();
        upgrade_latest_version.clear();
      }

      BOOST_LOG(info) << "Upgrade: checking for new release..."sv;

      // 1. Fetch latest release info
      std::string release_json = fetch_url(
        "https://api.github.com/repos/qtkksd/legiongames-sunshine/releases/latest"
      );

      if (release_json.empty()) {
        std::lock_guard<std::mutex> lock(upgrade_mutex);
        upgrade_last_error = "Failed to fetch release information from GitHub";
        upgrade_in_progress.store(false);
        return;
      }

      nlohmann::json release;
      try {
        release = nlohmann::json::parse(release_json);
      } catch (...) {
        std::lock_guard<std::mutex> lock(upgrade_mutex);
        upgrade_last_error = "Failed to parse release JSON";
        upgrade_in_progress.store(false);
        return;
      }

      std::string tag_name = release.value("tag_name", "");
      if (tag_name.empty()) {
        std::lock_guard<std::mutex> lock(upgrade_mutex);
        upgrade_last_error = "Release JSON missing tag_name";
        upgrade_in_progress.store(false);
        return;
      }

      std::string asset_url;
      if (release.contains("assets") && release["assets"].is_array()) {
        for (const auto &asset : release["assets"]) {
          if (asset.value("name", "") == "Sunshine-Windows-AMD64-installer.exe") {
            asset_url = asset.value("browser_download_url", "");
            break;
          }
        }
      }

      if (asset_url.empty()) {
        std::lock_guard<std::mutex> lock(upgrade_mutex);
        upgrade_last_error = "Installer asset not found in release";
        upgrade_in_progress.store(false);
        return;
      }

      // 2. Fetch tag commit SHA
      std::string tag_ref_json = fetch_url(
        "https://api.github.com/repos/qtkksd/legiongames-sunshine/git/ref/tags/" + tag_name
      );

      std::string latest_commit;
      if (!tag_ref_json.empty()) {
        try {
          nlohmann::json tag_ref = nlohmann::json::parse(tag_ref_json);
          if (tag_ref.contains("object") && tag_ref["object"].contains("sha")) {
            latest_commit = tag_ref["object"]["sha"].get<std::string>();
          }
        } catch (...) {
          BOOST_LOG(warning) << "Upgrade: failed to parse tag reference JSON"sv;
        }
      }

      {
        std::lock_guard<std::mutex> lock(upgrade_mutex);
        upgrade_latest_version = latest_commit.empty() ? tag_name : latest_commit;
      }

      // 3. Compare with current version
      if (!force && !latest_commit.empty() && latest_commit == upgrade_current_version) {
        std::lock_guard<std::mutex> lock(upgrade_mutex);
        upgrade_last_error = "";
        upgrade_in_progress.store(false);
        BOOST_LOG(info) << "Upgrade: already up to date (commit "sv << latest_commit << ")"sv;
        return;
      }

      if (force) {
        BOOST_LOG(info) << "Upgrade: force flag set, skipping version check"sv;
      }

      BOOST_LOG(info) << "Upgrade: new version available, downloading installer..."sv;

      // 4. Download installer
      std::error_code temp_ec;
      std::filesystem::path temp_dir = std::filesystem::temp_directory_path(temp_ec);
      if (temp_ec) {
        std::lock_guard<std::mutex> lock(upgrade_mutex);
        upgrade_last_error = "Failed to get temp directory: " + temp_ec.message();
        upgrade_in_progress.store(false);
        return;
      }

      std::filesystem::path installer_path = temp_dir / "sunshine_upgrade_installer.exe";

      if (!http::download_file(asset_url, installer_path.string())) {
        std::error_code rm_ec;
        std::filesystem::remove(installer_path, rm_ec);
        std::lock_guard<std::mutex> lock(upgrade_mutex);
        upgrade_last_error = "Failed to download installer";
        upgrade_in_progress.store(false);
        return;
      }

      BOOST_LOG(info) << "Upgrade: installer downloaded (rollback_on_failure="sv << rollback_on_failure << "), running silent install..."sv;

#ifdef _WIN32
      if (rollback_on_failure) {
        // Arm the health supervisor BEFORE installing: it survives the service
        // swap and rolls back to this version if the new build never comes online.
        arm_update_supervisor(upgrade_current_version, latest_commit);
      }
#endif

      // 5. Run installer
      std::error_code ec;
      boost::filesystem::path working_dir = boost::filesystem::path(installer_path.string()).parent_path();
      boost::process::v1::environment env = boost::this_process::environment();
      const std::string install_cmd = std::format("\"{}\" /S /SD IDNO", installer_path.string());

      auto child = platf::run_command(true, false, install_cmd, working_dir, env, nullptr, ec, nullptr);

      if (ec || !child.valid()) {
        std::error_code rm_ec;
        std::filesystem::remove(installer_path, rm_ec);
        std::lock_guard<std::mutex> lock(upgrade_mutex);
        upgrade_last_error = "Failed to start installer: " + ec.message();
        upgrade_in_progress.store(false);
        return;
      }

      child.wait(ec);

      if (ec) {
        std::error_code rm_ec;
        std::filesystem::remove(installer_path, rm_ec);
        std::lock_guard<std::mutex> lock(upgrade_mutex);
        upgrade_last_error = "Installer process error: " + ec.message();
        upgrade_in_progress.store(false);
        return;
      }

      int exit_code = child.exit_code();
      if (exit_code != 0) {
        std::error_code rm_ec;
        std::filesystem::remove(installer_path, rm_ec);
        std::lock_guard<std::mutex> lock(upgrade_mutex);
        upgrade_last_error = std::format("Installer exited with code {}", exit_code);
        upgrade_in_progress.store(false);
        return;
      }

      // 6. Clean up installer
      std::filesystem::remove(installer_path, ec);

      BOOST_LOG(info) << "Upgrade: installation complete, restarting Sunshine..."sv;

      // 7. Restart
      platf::restart();
    }

    void netbird_update_background_task() {
      netbird_update_in_progress.store(true);
      netbird_update_error.clear();

      BOOST_LOG(info) << "NetBird update: downloading installer..."sv;

      // 1. Download installer
      std::error_code ec;
      std::filesystem::path temp_dir = std::filesystem::temp_directory_path(ec);
      if (ec) {
        netbird_update_error = "Failed to get temp directory: " + ec.message();
        netbird_update_in_progress.store(false);
        return;
      }

      std::filesystem::path installer_path = temp_dir / "netbird_update_installer.exe";

      if (!http::download_file("https://pkgs.legiongames.ru/latest/windows/x64/netbird.exe", installer_path.string())) {
        std::filesystem::remove(installer_path, ec);
        netbird_update_error = "Failed to download NetBird installer";
        netbird_update_in_progress.store(false);
        return;
      }

      // 2. Stop NetBird service (ignore errors if not running)
      ec.clear();
      boost::filesystem::path working_dir;
      auto stop_child = platf::run_command(true, false, "net stop \"netbird\"", working_dir, {}, nullptr, ec, nullptr);
      if (!ec && stop_child.valid()) {
        stop_child.wait();
      }

      BOOST_LOG(info) << "NetBird update: running silent install..."sv;

      // 3. Run installer
      ec.clear();
      boost::filesystem::path install_working_dir = boost::filesystem::path(installer_path.string()).parent_path();
      boost::process::v1::environment env = boost::this_process::environment();
      const std::string install_cmd = std::format("\"{}\" /S /SD IDNO", installer_path.string());

      auto child = platf::run_command(true, false, install_cmd, install_working_dir, env, nullptr, ec, nullptr);

      if (ec || !child.valid()) {
        std::filesystem::remove(installer_path, ec);
        netbird_update_error = "Failed to start NetBird installer: " + ec.message();
        netbird_update_in_progress.store(false);
        return;
      }

      child.wait(ec);

      // 4. Start NetBird service
      ec.clear();
      auto start_child = platf::run_command(true, false, "net start \"netbird\"", working_dir, {}, nullptr, ec, nullptr);
      if (!ec && start_child.valid()) {
        start_child.wait();
      }

      // 5. Cleanup
      std::filesystem::remove(installer_path, ec);

      netbird_update_in_progress.store(false);
      BOOST_LOG(info) << "NetBird update: complete"sv;
    }
  }  // anonymous namespace

  /**
   * @brief Get upgrade status.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/upgrade/status| GET| null}
   */
  void getUpgradeStatus(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    print_req(request);

    nlohmann::json output_tree;
    output_tree["in_progress"] = upgrade_in_progress.load();
    output_tree["current_version"] = upgrade_current_version;

    {
      std::lock_guard<std::mutex> lock(upgrade_mutex);
      output_tree["latest_version"] = upgrade_latest_version;
      output_tree["error"] = upgrade_last_error;
    }

#ifdef _WIN32
    // Persisted update-supervisor state (phase: preparing/verifying/success/rolled_back).
    const auto state = read_upgrade_state();
    if (!state.empty()) {
      output_tree["phase"] = state.value("phase", "");
      output_tree["from_commit"] = state.value("from_commit", "");
      output_tree["to_commit"] = state.value("to_commit", "");
    }
#endif

    send_response(response, output_tree);
  }

  /**
   * @brief Lightweight health probe used by the update supervisor.
   * @details Unauthenticated on purpose: the update supervisor runs as SYSTEM and
   *          polls it over loopback to confirm the new build came online.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/health| GET| null}
   */
  void getHealth(const resp_https_t &response, const req_https_t &) {
    nlohmann::json output_tree;
    output_tree["status"] = "ok";
    output_tree["commit"] = std::string(PROJECT_VERSION_COMMIT);
    send_response(response, output_tree);
  }

  /**
   * @brief Trigger an upgrade to the latest release.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/upgrade| POST| null}
   */
  void doUpgrade(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    // Parse flags from request body
    bool force = false;
    bool rollback_on_failure = true;
    try {
      auto body = nlohmann::json::parse(request->content.string());
      force = body.value("force", false);
      rollback_on_failure = body.value("rollback_on_failure", true);
    } catch (...) {}

    nlohmann::json output_tree;

#ifdef _WIN32
    bool expected = false;
    if (!upgrade_in_progress.compare_exchange_strong(expected, true)) {
      output_tree["status"] = false;
      output_tree["error"] = "Upgrade already in progress";
      send_response(response, output_tree);
      return;
    }

    std::thread upgrade_thread(upgrade_background_task, force, rollback_on_failure);
    upgrade_thread.detach();

    output_tree["status"] = true;
    output_tree["message"] = "Upgrade started";
#else
    output_tree["status"] = false;
    output_tree["error"] = "Upgrade is only available on Windows";
#endif

    send_response(response, output_tree);
  }

  /**
   * @brief Get NetBird update status.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/update-netbird/status| GET| null}
   */
  void getNetBirdUpdateStatus(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    print_req(request);

    nlohmann::json output_tree;
    output_tree["in_progress"] = netbird_update_in_progress.load();
    output_tree["error"] = netbird_update_error;

    send_response(response, output_tree);
  }

  /**
   * @brief Update NetBird client to the latest version.
   * @param response The HTTP response object.
   * @param request The HTTP request object.
   *
   * @api_examples{/api/update-netbird| POST| null}
   */
  void doNetBirdUpdate(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    nlohmann::json output_tree;

#ifdef _WIN32
    bool expected = false;
    if (!netbird_update_in_progress.compare_exchange_strong(expected, true)) {
      output_tree["status"] = false;
      output_tree["error"] = "NetBird update already in progress";
      send_response(response, output_tree);
      return;
    }

    std::thread update_thread(netbird_update_background_task);
    update_thread.detach();

    output_tree["status"] = true;
    output_tree["message"] = "NetBird update started";
#else
    output_tree["status"] = false;
    output_tree["error"] = "NetBird update is only available on Windows";
#endif

    send_response(response, output_tree);
  }

#ifdef _WIN32
  /**
   * @brief Run the DiskGuard helper (lgd.exe) shipped next to sunshine.exe and
   * parse its JSON stdout.
   * @param args Command line arguments for lgd.exe (e.g. "status").
   * @param out Parsed JSON output.
   * @param error Error message when the call fails.
   * @return True when lgd.exe exited 0 and produced parseable JSON.
   */
  bool run_diskguard(const std::string &args, nlohmann::json &out, std::string &error) {
    const std::filesystem::path exe = platf::appdata().parent_path() / "lgd.exe";
    if (!std::filesystem::exists(exe)) {
      error = "lgd.exe not found next to Sunshine: " + exe.string();
      return false;
    }

    std::error_code ec;
    boost::filesystem::path working_dir;
    const std::string cmd = std::format("\"{}\" {}", exe.string(), args);

    FILE *tmp = std::tmpfile();
    if (!tmp) {
      error = "tmpfile() failed";
      return false;
    }

    auto child = platf::run_command(true, false, cmd, working_dir, {}, tmp, ec, nullptr);
    if (ec || !child.valid()) {
      std::fclose(tmp);
      error = "failed to start lgd.exe: " + ec.message();
      return false;
    }

    child.wait();
    const int exit_code = child.exit_code();
    std::rewind(tmp);

    std::string content;
    char buffer[4096];
    while (std::fgets(buffer, sizeof(buffer), tmp)) {
      content += buffer;
    }
    std::fclose(tmp);

    if (!content.empty()) {
      BOOST_LOG(info) << "DiskGuard [" << args << "] exit=" << exit_code << " out=" << content;
    }

    try {
      out = nlohmann::json::parse(content);
    } catch (...) {
      // lgd may mix stderr log lines with its JSON stdout; retry on the
      // trailing JSON object (the last line that begins with '{').
      std::string trimmed = content;
      const auto pos = content.rfind("\n{");
      if (pos != std::string::npos) {
        trimmed = content.substr(pos + 1);
      } else if (const auto b = content.find('{'); b != std::string::npos) {
        trimmed = content.substr(b);
      }
      try {
        out = nlohmann::json::parse(trimmed);
      } catch (...) {
        out = nlohmann::json::object();
        out["raw"] = content;
      }
    }

    if (exit_code != 0) {
      if (out.is_object() && out.contains("error") && out["error"].is_string()) {
        error = out["error"].get<std::string>();
      } else {
        error = std::format("lgd.exe {} failed (exit {})", args, exit_code);
      }
      return false;
    }
    return true;
  }
#endif

  /**
   * @brief Get DiskGuard status (version, last snapshot, shadows).
   * @api_examples{/api/diskguard/status| GET| null}
   */
  void getDiskGuardStatus(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    print_req(request);

    nlohmann::json output_tree;
#ifdef _WIN32
    std::string error;
    if (!run_diskguard("status", output_tree, error)) {
      if (!output_tree.is_object() || output_tree.empty()) {
        output_tree = nlohmann::json::object();
      }
      output_tree["status"] = false;
      output_tree["error"] = error;
    }
#else
    output_tree = {{"status", false}, {"error", "DiskGuard is only available on Windows"}};
#endif
    send_response(response, output_tree);
  }

  /**
   * @brief Create a new DiskGuard gold snapshot.
   * @api_examples{/api/diskguard/snapshot| POST| null}
   */
  void doDiskGuardSnapshot(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    nlohmann::json output_tree;
#ifdef _WIN32
    std::string error;
    if (!run_diskguard("snapshot", output_tree, error)) {
      if (!output_tree.is_object() || output_tree.empty()) {
        output_tree = nlohmann::json::object();
      }
      output_tree["status"] = false;
      output_tree["error"] = error;
    }
#else
    output_tree = {{"status", false}, {"error", "DiskGuard is only available on Windows"}};
#endif
    send_response(response, output_tree);
  }

  /**
   * @brief Revert the protected volume to the gold snapshot.
   * @api_examples{/api/diskguard/revert| POST| null}
   *
   * Optional JSON body {"index": N, "dry_run": bool}:
   *   index   - snapshot by age (0 = newest, default; 1 = previous)
   *   dry_run - plan only, make no changes
   */
  void doDiskGuardRevert(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    std::string args = "revert";
    try {
      auto body = nlohmann::json::parse(request->content.string());
      if (body.contains("index")) {
        args += std::format(" --index {}", body["index"].get<int>());
      }
      if (body.value("dry_run", false)) {
        args += " --dry-run";
      }
    } catch (...) {}

    nlohmann::json output_tree;
#ifdef _WIN32
    std::string error;
    if (!run_diskguard(args, output_tree, error)) {
      if (!output_tree.is_object() || output_tree.empty()) {
        output_tree = nlohmann::json::object();
      }
      output_tree["status"] = false;
      output_tree["error"] = error;
    }
#else
    output_tree = {{"status", false}, {"error", "DiskGuard is only available on Windows"}};
#endif
    send_response(response, output_tree);
  }

  /**
   * @brief Self-update the DiskGuard binary.
   * @api_examples{/api/diskguard/update| POST| null}
   */
  void doDiskGuardUpdate(const resp_https_t &response, const req_https_t &request) {
    if (!authenticate(response, request)) {
      return;
    }

    std::string client_id = get_client_id(request);
    if (!validate_csrf_token(response, request, client_id)) {
      return;
    }

    print_req(request);

    nlohmann::json output_tree;
#ifdef _WIN32
    std::string error;
    if (!run_diskguard("update", output_tree, error)) {
      if (!output_tree.is_object() || output_tree.empty()) {
        output_tree = nlohmann::json::object();
      }
      output_tree["status"] = false;
      output_tree["error"] = error;
    }
#else
    output_tree = {{"status", false}, {"error", "DiskGuard is only available on Windows"}};
#endif
    send_response(response, output_tree);
  }

  /**
   * @brief Start the HTTPS configuration server.
   */
  void start() {
    platf::set_thread_name("confighttp");

#ifdef _WIN32
    // Startup self-heal: re-enable any physical input left disabled by a
    // previous session (for example after an unexpected reboot/power loss).
    self_heal_input_state();
#endif

    const auto shutdown_event = mail::man->event<bool>(mail::shutdown);

    const auto port_https = net::map_port(PORT_HTTPS);
    const auto address_family = net::af_from_enum_string(config::sunshine.address_family);

    https_server_t server {config::nvhttp.cert, config::nvhttp.pkey};

    // Helper to create page handler lambdas without repeating the signature
    auto page_handler = [](const char *file, bool require_auth = true, bool redirect_if_username = false) {
      return [file, require_auth, redirect_if_username](const resp_https_t &response, const req_https_t &request) {
        getPage(response, request, file, require_auth, redirect_if_username);
      };
    };

    // Default resource handlers
    const https_handler_t bad_request_handler = [](const resp_https_t &response, const req_https_t &request) {
      bad_request(response, request);
    };
    const https_handler_t not_found_handler = [](const resp_https_t &response, const req_https_t &request) {
      not_found(response, request);
    };

    // error by default
    server.default_resource["DELETE"] = bad_request_handler;
    server.default_resource["PATCH"] = bad_request_handler;
    server.default_resource["POST"] = bad_request_handler;
    server.default_resource["PUT"] = bad_request_handler;
    server.default_resource["GET"] = not_found_handler;

    // web pages
    server.resource["^/$"]["GET"] = page_handler("index.html");
    server.resource["^/apps/?$"]["GET"] = page_handler("apps.html");
    server.resource["^/clients/?$"]["GET"] = page_handler("clients.html");
    server.resource["^/config/?$"]["GET"] = page_handler("config.html");
    server.resource["^/featured/?$"]["GET"] = page_handler("featured.html");
    server.resource["^/logout/?$"]["GET"] = page_handler("logout.html", false);
    server.resource["^/password/?$"]["GET"] = page_handler("password.html");
    server.resource["^/pin/?$"]["GET"] = page_handler("pin.html");
    server.resource["^/troubleshooting/?$"]["GET"] = page_handler("troubleshooting.html");
    server.resource["^/welcome/?$"]["GET"] = page_handler("welcome.html", false, true);

    // rest api
    server.resource["^/api/browse$"]["GET"] = browseDirectory;
    server.resource["^/api/apps$"]["GET"] = getApps;
    server.resource["^/api/apps$"]["POST"] = saveApp;
    server.resource["^/api/apps/([0-9]+)$"]["DELETE"] = deleteApp;
    server.resource["^/api/apps/close$"]["POST"] = closeApp;
    server.resource["^/api/clients/list$"]["GET"] = getClients;
    server.resource["^/api/clients/unpair$"]["POST"] = unpair;
    server.resource["^/api/clients/unpair-all$"]["POST"] = unpairAll;
    server.resource["^/api/clients/update$"]["POST"] = updateClient;
    server.resource["^/api/config$"]["GET"] = getConfig;
    server.resource["^/api/config$"]["POST"] = saveConfig;
    server.resource["^/api/configLocale$"]["GET"] = getLocale;
    server.resource["^/api/covers/([0-9]+)$"]["GET"] = getCover;
    server.resource["^/api/covers/upload$"]["POST"] = uploadCover;
    server.resource["^/api/csrf-token$"]["GET"] = getCSRFToken;
    server.resource["^/api/password$"]["POST"] = savePassword;
    server.resource["^/api/pin$"]["POST"] = savePin;
    server.resource["^/api/logs$"]["GET"] = getLogs;
    server.resource["^/api/reset-display-device-persistence$"]["POST"] = resetDisplayDevicePersistence;
    server.resource["^/api/restart$"]["POST"] = restart;
    server.resource["^/api/vigembus/status$"]["GET"] = getViGEmBusStatus;
    server.resource["^/api/vigembus/install$"]["POST"] = installViGEmBus;
    server.resource["^/api/input-block/status$"]["GET"] = getInputBlockStatus;
    server.resource["^/api/input-block/block$"]["POST"] = blockInput;
    server.resource["^/api/input-block/unblock$"]["POST"] = unblockInput;
    server.resource["^/api/input-block/recover$"]["POST"] = recoverInput;
    server.resource["^/api/input-block/monitor/off$"]["POST"] = monitorOff;
    server.resource["^/api/input-block/monitor/on$"]["POST"] = monitorOn;
    server.resource["^/api/health$"]["GET"] = getHealth;
    server.resource["^/api/upgrade/status$"]["GET"] = getUpgradeStatus;
    server.resource["^/api/upgrade$"]["POST"] = doUpgrade;
    server.resource["^/api/update-netbird/status$"]["GET"] = getNetBirdUpdateStatus;
    server.resource["^/api/update-netbird$"]["POST"] = doNetBirdUpdate;
    server.resource["^/api/diskguard/status$"]["GET"] = getDiskGuardStatus;
    server.resource["^/api/diskguard/snapshot$"]["POST"] = doDiskGuardSnapshot;
    server.resource["^/api/diskguard/revert$"]["POST"] = doDiskGuardRevert;
    server.resource["^/api/diskguard/update$"]["POST"] = doDiskGuardUpdate;

    // static/dynamic resources
    server.resource["^/images/sunshine.ico$"]["GET"] = getFaviconImage;
    server.resource["^/images/logo-sunshine-45.png$"]["GET"] = getSunshineLogoImage;
    server.resource["^/assets\\/.+$"]["GET"] = getAsset;

    server.config.reuse_address = true;
    server.config.address = net::get_bind_address(address_family);
    server.config.port = port_https;

    // Store bind address for logging, use "localhost" as fallback for wildcard addresses
    const auto bind_addr = server.config.address;
    const auto display_addr = config::sunshine.bind_address.empty() ? "localhost"sv : std::string_view {bind_addr};

    auto accept_and_run = [&](auto *server) {
      try {
        platf::set_thread_name("confighttp::tcp");
        server->start([&display_addr](const unsigned short port) {
          BOOST_LOG(info) << "Configuration UI available at [https://"sv << display_addr << ":" << port << "]";
        });
      } catch (boost::system::system_error &err) {
        // It's possible the exception gets thrown after calling server->stop() from a different thread
        if (shutdown_event->peek()) {
          return;
        }

        BOOST_LOG(fatal) << "Couldn't start Configuration HTTPS server on port ["sv << port_https << "]: "sv << err.what();
        shutdown_event->raise(true);
        return;
      }
    };
    std::jthread tcp {accept_and_run, &server};

    // Wait for any event
    shutdown_event->view();

#ifdef _WIN32
    // Restore physical input and display on graceful shutdown so a service
    // stop/restart never leaves the machine with a disabled keyboard or a dark screen.
    restore_input_state();
#endif

    server.stop();

    tcp.join();
  }
}  // namespace confighttp
