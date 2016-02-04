#include "AccessControl.hh"

#include <fstream>

#include "Common.hh"

#include "Controller.hh"
#include "Config.hh"
#include <fluid/of13msg.hh>
#include <tins/ethernetII.h>
#include <tins/ip.h>
#include <tins/icmp.h>

#include "json11.hpp"

constexpr auto ARP_ETH_TYPE = 0x0806;
constexpr auto ICMP_PROTO = 1;
constexpr auto DEST_UNREACHABLE_ADM = 0x0d;

REGISTER_APPLICATION(AccessControl, {"controller", ""})

void AccessControl::init(Loader *loader, const Config& config)
{
    Controller* ctrl = Controller::get(loader);
    ctrl->registerHandler(this);
    m_table.reset(new AccessTable());
    JSONTableParser::parseFile("./access_control_config.json", *m_table.get());
}

OFMessageHandler::Action AccessControl::Handler::processMiss(OFConnection* ofconn, Flow* flow)
{

    if (flow->loadEthType() == ARP_ETH_TYPE || (flow->loadEthType() == 0x0800 && flow->loadIPProto() == ICMP_PROTO) ) {
        if (m_table->match(*flow)) {
            LOG(INFO) << (flow->pkt()->readEthType() == ARP_ETH_TYPE ? "ARP" : "ICMP") << " flow PASSED from host: "
                << flow->loadEthSrc().to_string() << " to host: " << flow->loadEthDst().to_string();
            flow->setFlags(Flow::Disposable);
            return Continue;
        }
        else if (flow->pkt()->readIPProto() == ICMP_PROTO ||
                 flow->pkt()->readEthType() == ARP_ETH_TYPE) {
            LOG(INFO) << (flow->pkt()->readEthType() == ARP_ETH_TYPE ? "ARP" : "ICMP") << " flow DENIED from host: "
                << flow->loadEthSrc().to_string() << " to host: " << flow->loadEthDst().to_string();
            flow->setFlags(Flow::Disposable); // Unnecessary line, but it's easier to debug with it
            return Stop;
        }
    }

    return Continue;
}

std::unique_ptr<OFMessageHandler> AccessControl::makeOFMessageHandler()
{
    return std::unique_ptr<Handler>(new Handler(m_table));
}

bool AccessControl::AccessTable::match(Flow& flow) const
{
    EthAddress src_addr = flow.loadEthSrc();
    std::map<std::string, Rule>::const_iterator entry = entries.find(src_addr.to_string());
    if (entry != entries.cend())
        return def_rule.match(flow) || entry->second.match(flow);

    return false;
}

bool AccessControl::AccessTable::Rule::match(Flow &flow) const
{
    if (flow.match(of13::EthType(ARP_ETH_TYPE)))
        return allow_arp;

    bool is_icmp = flow.match(of13::IPProto(ICMP_PROTO));

    if (is_icmp) {
        return (allowed_hosts.find(flow.loadIPv4Dst().getIPv4()) != allowed_hosts.cend());
    }

    return false;
}

void AccessControl::JSONTableParser::parseFile(const std::string &filename, AccessControl::AccessTable& table) {
    LOG(INFO) << "Parsing config file " << filename;

    std::ifstream file(filename);

    std::string file_str((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());

    std::string err;
    err.clear();

    auto json = json11::Json::parse(file_str, err).object_items();
    if (!err.empty())
    {
        LOG(ERROR) << "JSON parsing error - " << err;
        return;
    }
    auto def_rule = config_cd(json, "def-rule");
    table.def_rule.allow_arp = config_get(def_rule, "allow-arp", false);
    auto hosts = config_get_array(def_rule, "hosts");

    for (const auto& host : hosts) {
        table.def_rule.allowed_hosts.insert(IPAddress::IPv4from_string(host.string_value()));
    }

    auto entries = config_cd(json, "clients");
    for (const auto& entry : entries)
    {
        AccessTable::Rule rule;
        auto rule_json = entry.second.object_items();
        rule.allow_arp = config_get(rule_json, "allow-arp", false);
        auto hosts = config_get_array(rule_json, "hosts");
        for (const auto& host : hosts)
            rule.allowed_hosts.insert(IPAddress::IPv4from_string(host.string_value()));
        table.entries[entry.first] = rule;
    }
}