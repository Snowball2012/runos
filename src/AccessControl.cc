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
    m_table->def_rule.allow_arp = true;
}

OFMessageHandler::Action AccessControl::Handler::processMiss(OFConnection* ofconn, Flow* flow)
{

    if (m_table->match(*flow))
    {
        LOG(INFO) << (flow->pkt()->readEthType() == ARP_ETH_TYPE ? "ARP" : "ICMP") << " flow passed from host: " << flow->loadEthSrc().to_string();
        return Continue;
    }
    else if (flow->match(of13::IPProto(ICMP_PROTO)) || flow->pkt()->readEthType() == ARP_ETH_TYPE)
    {
        LOG(INFO) << (flow->pkt()->readEthType() == ARP_ETH_TYPE ? "ARP" : "ICMP") << " flow denied from host: " << flow->loadEthSrc().to_string();
        // Ignore the flow
        /*flow->setFlags(Flow::Disposable);
        Tins::IP pdu(Tins::IP::address_type(flow->loadIPv4Src().getIPv4()),
                     Tins::IP::address_type(flow->loadIPv4Dst().getIPv4()));

        Tins::ICMP icmp(Tins::ICMP::DEST_UNREACHABLE);
        icmp.code(DEST_UNREACHABLE_ADM);
        pdu /= icmp;

        Tins::PDU::serialization_type ser = pdu.serialize();
        uint8_t* data = &(ser[0]);
        of13::PacketOut out;
        out.buffer_id(OFP_NO_BUFFER);
        out.data(data, ser.size());
        of13::OutputAction action(flow->pkt()->readInPort(), 0);
        out.add_action(action);

        uint8_t* buffer = out.pack();
        ofconn->send(buffer, out.length());
        OFMsg::free_buffer(buffer);*/

        return Stop;
    }
    else
    {
        return Continue;
    }
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

    if (is_icmp)
        return (allowed_hosts.find(flow.loadIPv4Dst().getIPv4()) != allowed_hosts.cend());

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
    auto hosts = config_cd(def_rule, "hosts");
    for (const auto& host : hosts)
        table.def_rule.allowed_hosts.insert(IPAddress::IPv4from_string(host.first));

    auto entries = config_cd(json, "clients");
    for (const auto& entry : entries)
    {
        AccessTable::Rule rule;
        auto rule_json = entry.second.object_items();
        rule.allow_arp = config_get(rule_json, "allow-arp", false);
        auto hosts = config_cd(rule_json, "hosts");
        for (const auto& host : hosts)
            rule.allowed_hosts.insert(IPAddress::IPv4from_string(host.first));
        table.entries[entry.first] = rule;
    }
}