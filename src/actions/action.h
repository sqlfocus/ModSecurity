/*
 * ModSecurity, http://www.modsecurity.org/
 * Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */

#include <string>
#include <iostream>

#include "modsecurity/intervention.h"
#include "modsecurity/rule.h"

#ifndef SRC_ACTIONS_ACTION_H_
#define SRC_ACTIONS_ACTION_H_

#ifdef __cplusplus

namespace modsecurity {
class Transaction;
class Rule;

namespace actions {


class Action {
 public:
    explicit Action(const std::string& _action)
        : action_kind(2),
        m_isNone(false),
        m_name(""),
        m_parser_payload(""),
        temporaryAction(false) {
            set_name_and_payload(_action);
        }
    explicit Action(const std::string& _action, int kind)
        : action_kind(kind),
        m_isNone(false),
        m_name(""),
        m_parser_payload(""),
        temporaryAction(false) {
            set_name_and_payload(_action);
        }

    virtual ~Action() { }

    virtual std::string evaluate(std::string exp,
        Transaction *transaction);
    virtual bool evaluate(Rule *rule, Transaction *transaction);
    virtual bool evaluate(Rule *rule, Transaction *transaction,
        RuleMessage *ruleMessage) {
        return evaluate(rule, transaction);
    }
    virtual bool init(std::string *error) { return true; }
    virtual bool isDisruptive() { return false; }
    virtual void fillIntervention(ModSecurityIntervention *intervention);
    static Action *instantiate(const std::string& name);


    void set_name_and_payload(const std::string& data) {
        size_t pos = data.find(":");
        std::string t = "t:";

        if (data.compare(0, t.length(), t) == 0) {
            pos = data.find(":", 2);
        }

        if (pos == std::string::npos) {
            m_name = data;
            return;
        }

        m_name = std::string(data, 0, pos);
        m_parser_payload = std::string(data, pos + 1, data.length());

        if (m_parser_payload.at(0) == '\'' && m_parser_payload.size() > 2) {
            m_parser_payload.erase(0, 1);
            m_parser_payload.pop_back();
        }
    }

    bool m_isNone;
    bool temporaryAction;
    int action_kind;
    std::string m_name;
    std::string m_parser_payload;

    /**
     *
     * Define the action kind regarding to the execution time.
     * 
     * 
     */
    enum Kind {
    /**
     *
     * Action that are executed while loading the configuration. For instance
     * the rule ID or the rule phase.
     *
     * 当加载配置时，执行的动作
     */
     ConfigurationKind,
    /**
     *
     * Those are actions that demands to be executed before call the operator.
     * For instance the tranformations.
     *
     * 在执行operator之前，需要执行的动作；如，各种变换
     */
     RunTimeBeforeMatchAttemptKind,
    /**
     *
     * Actions that are executed after the execution of the operator, only if
     * the operator returned Match (or True). For instance the disruptive
     * actions.
     *
     * 在operator之后执行的动作，仅当operator匹配后才执行；如，破坏性行为
     */
     RunTimeOnlyIfMatchKind,
    };
};


}  // namespace actions
}  // namespace modsecurity

#endif

#endif  // SRC_ACTIONS_ACTION_H_
