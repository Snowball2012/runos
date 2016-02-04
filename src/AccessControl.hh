#pragma once

#include <memory>
#include <set>

#include "Application.hh"
#include "Loader.hh"

#include "Controller.hh"
#include "OFMessageHandler.hh"



class AccessControl : public Application, public OFMessageHandlerFactory {
SIMPLE_APPLICATION(AccessControl, "access_control_app")

    // I use uint32_t and std::strings instead of IPAddress and EthAddress
    // because a lot of 'const' qualifiers in those classes' methods declarations are missing
    // (e.g. most of the getters)
    struct AccessTable {
        struct Rule {
            bool allow_arp;
            std::set<uint32_t> allowed_hosts;

            bool match(Flow &flow) const;
        };

        std::map<std::string, Rule> entries;

        Rule def_rule;

        bool match(Flow &flow) const;
    };

    class JSONTableParser
    {
    public:
        static void parseFile(const std::string& filename, AccessTable& table);
    };

    class Handler: public OFMessageHandler {
        const std::shared_ptr<AccessTable> m_table;
    public:
        Handler(const std::shared_ptr<AccessTable> access_table) :m_table(access_table) {}
        Action processMiss(OFConnection* ofconn, Flow* flow) override;
    };

    std::shared_ptr<AccessTable> m_table;

public:
    void init(Loader* loader, const Config& config) override;

    std::string orderingName() const override { return "access_control"; }
    //bool isPrereq(const std::string& name) const override  { return (name == "arp-handler"); }
    bool isPostreq(const std::string& name) const override { return (name == "arp-handler"); }
    std::unique_ptr<OFMessageHandler> makeOFMessageHandler() override;

};


