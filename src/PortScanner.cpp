#include "PortScanner.hpp"

const std::unordered_map<uint16_t, std::string> PortScanner::basicPorts{
    {21, "FTP"},         {22, "SSH"},         {23, "TelNet"},  {25, "SMTP"},   {53, "DNS"},
    {67, "DHCP server"}, {68, "DHCP client"}, {80, "HTTP"},    {110, "POP3"},  {143, "IMAP"},
    {161, "SNMP"},       {443, "HTTPS"},      {445, "SMB"},    {465, "SMTPS"}, {993, "IMAPS"},
    {1080, "SOCKS"},     {1521, "ORACLE DB"}, {3306, "MySQL"}, {3389, "RDP"},  {5432, "PostgreSQL"},
    {6379, "Redis"},
};

void PortScanner::parse_port(std::string& port) {
    try {
        auto dash = port.find('-');

        if (dash == std::string::npos) {
            // single port, e.g. "-p 80"
            int p = std::stoi(port);
            if (p < 1 || p > MAX_PORT) {
                startPort = 1;
                endPort = MAX_PORT;
            } else {
                startPort = endPort = static_cast<uint16_t>(p);
            }
            return;
        }

        int start_port = std::stoi(port.substr(0, dash));
        int end_port = std::stoi(port.substr(dash + 1));

        if (start_port < 1 || end_port > MAX_PORT || start_port > end_port) {
            startPort = 1;
            endPort = MAX_PORT;
        } else {
            startPort = static_cast<uint16_t>(start_port);
            endPort = static_cast<uint16_t>(end_port);
        }
    } catch (const std::exception&) {
        // malformed input (non-numeric, empty, etc.) -> fall back to full range instead of crashing
        startPort = 1;
        endPort = MAX_PORT;
    }
}

PortScanner::PortScanner(std::string& domainName, std::string& port, int max_threads,
                         std::uint8_t expiry_time) {
    this->domainName = std::move(domainName);
    this->MAX_THREADS = max_threads > 0 ? max_threads : 1;
    this->expiry_time = expiry_time;

    parse_port(port);
    auto result = resolver.resolve(this->domainName, "");
    endpoint = *result.begin();

    setup_queue();
                         }

                         void PortScanner::setup_queue() {
                             q = std::queue<uint16_t>();
                             for (int i = startPort; i <= endPort; i++) {
                                 q.push(i);
                             }
                         }

                         void PortScanner::set_options(std::string& domainName, std::string& port, int max_threads,
                                                       std::uint8_t expiry_time) {
                             this->domainName = std::move(domainName);
                             this->MAX_THREADS = max_threads > 0 ? max_threads : 1;
                             this->expiry_time = expiry_time;
                             parse_port(port);

                             auto result = resolver.resolve(this->domainName, "");
                             endpoint = *result.begin();
                                                       }

                                                       void PortScanner::set_max_port(std::uint16_t port) {
                                                           endPort = port;
                                                       }
                                                       void PortScanner::set_max_threads(int value) {
                                                           MAX_THREADS = value > 0 ? value : 1;
                                                       }

                                                       void PortScanner::set_ip_address(std::string ip) {
                                                           domainName = std::move(ip);
                                                       }

                                                       void PortScanner::set_expiry_time(std::uint8_t value) {
                                                           expiry_time = value;
                                                       }

                                                       void PortScanner::set_verbose(bool value) {
                                                           verbose = value;
                                                       }

                                                       void PortScanner::start() {
                                                           setup_queue();
                                                           for (int i = 0; i < MAX_THREADS; i++) {
                                                               boost::asio::post(strand, [this]() { scan(); });
                                                           }
                                                       }

                                                       void PortScanner::run() {
                                                           printf("%-8s %-10s %-12s %s\n", "PORT", "STATE", "SERVICE", "BANNER");
                                                           printf("--------------------------------------------------------\n");
                                                           io.run();
                                                           printf("--------------------------------------------------------\n");
                                                           printf("Scan complete.\n");
                                                           printf("  Open:     %d\n", open_ports);
                                                           printf("  Closed:   %d\n", closed_ports);
                                                           printf("  Filtered: %d\n", filtered_ports);
                                                       }

                                                       void PortScanner::scan() {
                                                           if (q.empty() || cnt >= MAX_THREADS)
                                                               return;

                                                           uint16_t port = q.front();
                                                           q.pop();
                                                           ++cnt;

                                                           auto socket = std::make_shared<tcp::socket>(io);
                                                           auto timer = std::make_shared<boost::asio::steady_timer>(io);
                                                           auto complete = std::make_shared<bool>(false);

                                                           tcp::endpoint target_endpoint(this->endpoint.address(), port);

                                                           timer->expires_after(std::chrono::seconds(expiry_time));

                                                           timer->async_wait(boost::asio::bind_executor(
                                                               strand, [this, complete, socket, port](boost::system::error_code ec) {
                                                                   if (!ec && !*complete) {
                                                                       *complete = true;
                                                                       socket->close();
                                                                       if (verbose) {
                                                                           printf("%-8d %s%-10s%s %-12s %s\n", port, YELLOW, "FILTERED", RESET, "---",
                                                                                  "---");
                                                                       }
                                                                       ++filtered_ports;
                                                                       --cnt;
                                                                       scan();
                                                                   }
                                                               }));

                                                           socket->async_connect(target_endpoint,
                                                                                 boost::asio::bind_executor(strand, [this, socket, timer, port, complete](
                                                                                     boost::system::error_code ec) {
                                                                                     if (*complete)
                                                                                         return;
                                                                                     *complete = true;
                                                                                     timer->cancel();

                                                                                     std::string service = "---";
                                                                                     auto it = basicPorts.find(port);
                                                                                     if (it != basicPorts.end()) {
                                                                                         service = it->second;
                                                                                     }

                                                                                     if (!ec) {
                                                                                         auto banner = std::make_shared<std::string>("---");
                                                                                         auto buf = std::make_shared<std::array<char, 128>>();
                                                                                         auto banner_done = std::make_shared<bool>(false);
                                                                                         auto banner_timer = std::make_shared<boost::asio::steady_timer>(io);

                                                                                         // banner read gets its own short timeout so a silent/hung
                                                                                         // open port can't hold a thread slot forever
                                                                                         banner_timer->expires_after(std::chrono::seconds(expiry_time));
                                                                                         banner_timer->async_wait(boost::asio::bind_executor(
                                                                                             strand, [this, socket, port, banner, service, banner_done](
                                                                                                 boost::system::error_code ec) {
                                                                                                 if (!ec && !*banner_done) {
                                                                                                     *banner_done = true;
                                                                                                     socket->close();
                                                                                                     printf("%-8d %s%-10s%s %-12s %s\n", port, GREEN,
                                                                                                            "OPEN", RESET, service.c_str(),
                                                                                                            banner->c_str());
                                                                                                     ++open_ports;
                                                                                                     --cnt;
                                                                                                     scan();
                                                                                                 }
                                                                                                 }));

                                                                                         socket->async_read_some(
                                                                                             boost::asio::buffer(*buf),
                                                                                                                 boost::asio::bind_executor(
                                                                                                                     strand, [this, port, buf, banner, service, banner_done,
                                                                                                                     banner_timer](boost::system::error_code ec,
                                                                                                                                   std::size_t n) {
                                                                                                                         if (*banner_done)
                                                                                                                             return;
                                                                                                                         *banner_done = true;
                                                                                                                         banner_timer->cancel();

                                                                                                                         if (!ec && n > 0) {
                                                                                                                             banner->assign(buf->data(), n);
                                                                                                                         }
                                                                                                                         printf("%-8d %s%-10s%s %-12s %s\n", port, GREEN,
                                                                                                                                "OPEN", RESET, service.c_str(),
                                                                                                                                banner->c_str());
                                                                                                                         ++open_ports;
                                                                                                                         --cnt;
                                                                                                                         scan();
                                                                                                                                   }));

                                                                                     } else {
                                                                                         if (verbose) {
                                                                                             printf("%-8d %s%-10s%s %-12s %s\n", port, RED, "CLOSED",
                                                                                                    RESET, service.c_str(), "---");
                                                                                         }
                                                                                         ++closed_ports;
                                                                                         --cnt;
                                                                                         scan();
                                                                                     }
                                                                                     }));
                                                       }
