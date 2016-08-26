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

/** @file modsecurity.h Main ModSecurity header file */

/** @mainpage ModSecurity - open source, cross platform web application firewall
 *
 * Example Usage:
 * @code
 *
 * using ModSecurity::ModSecurity;
 * using ModSecurity::Rules;
 * using ModSecurity::Transaction;
 *
 * ModSecurity *modsec;
 * ModSecurity::Rules *rules;
 *
 * modsec = new ModSecurity();
 * rules = new Rules();
 * rules->loadFromUri(rules_file);
 *
 * Transaction *modsecTransaction = new Transaction(modsec, rules);
 * modsecTransaction->processConnection("127.0.0.1");
 *
 * if (modsecTransaction->intervention()) {
 *     std::cout << "There is an intervention" << std::endl;
 * }
 *
 * ...      
 *
 * @endcode
 * 
 */

/**
 * @defgroup ModSecurity_C_API ModSecurity C API
 *
 * This is the ModSecurity C API description
 *
 * At this page you can get information on how the extend your C
 * application, by embedding ModSecurity.
 *
 */


/**
 * @defgroup ModSecurity_CPP_API ModSecurity CPP API
 *
 * This is the ModSecurity CPP API description.
 *
 * At this page you can get information on how the extend your CPP
 * application, by embedding ModSecurity.
 *
 */


/**
 * @defgroup ModSecurity_Operator ModSecurity Operators
 *
 * SecLanguage operator
 */


#ifdef __cplusplus
#include <ctime>
#include <iostream>
#include <string>
#endif


#ifndef HEADERS_MODSECURITY_MODSECURITY_H_
#define HEADERS_MODSECURITY_MODSECURITY_H_


#ifndef __cplusplus
typedef struct ModSecurity_t modsecurity;
#endif


#include "modsecurity/intervention.h"
#include "modsecurity/transaction.h"
#include "modsecurity/debug_log.h"
#include "modsecurity/rules.h"

/**
 * TAG_NUM:
 *
 * Alpha  - 001
 * Beta   - 002
 * Dev    - 010
 * Rc1    - 051
 * Rc2    - 052
 * ...    - ...
 * Release- 100
 *
 */

#define MODSECURITY_MAJOR "3"
#define MODSECURITY_MINOR "0"
#define MODSECURITY_PATCHLEVEL "0"
#define MODSECURITY_TAG "-alpha"
#define MODSECURITY_TAG_NUM "001"

#define MODSECURITY_VERSION MODSECURITY_MAJOR "." \
    MODSECURITY_MINOR "." MODSECURITY_PATCHLEVEL \
    MODSECURITY_TAG

#define MODSECURITY_VERSION_NUM MODSECURITY_MAJOR \
    MODSECURITY_MINOR MODSECURITY_PATCHLEVEL MODSECURITY_TAG_NUM

typedef void (*LogCb) (void *, const char *);

#ifdef __cplusplus
namespace modsecurity {

/* few forwarded declarations */
namespace actions {
class Action;
}
namespace operators {
class Operators;
}
class Rule;

/** @ingroup ModSecurity_CPP_API */
/* 安全模块儿的类定义 */
class ModSecurity {
 public:
    ModSecurity();
    ~ModSecurity();

    static const std::string whoAmI();
    void setConnectorInformation(std::string connector);
    void setServerLogCb(LogCb cb);
    void serverLog(void *data, const std::string& msg);
    const std::string& getConnectorInformation();

    /**
     *
     * The Phases enumerator consists in mapping the different stages of a
     * given request. ModSecurity is expected to inspect data based on those
     * "phases". If your module/application use this in a different order, it
     * will lead ModSecurity to act in an unexpected behavior.
     *
     * It is mandatory to call all the phases, even if you don't have this
     * phases segmented in your end.
     * 
     * Phases枚举定义了请求处理的不同阶段，ModSecurity模块儿基于这些阶段检查
     * 数据。如果对接的引擎，处理请求的顺序和此处定义不一致，很可能导致ModS
     * 发生不可预期的异常。
     * 
     * 注意，这些阶段是被强制顺序处理的
     */
    enum Phases {
    /**
     *
     * The connection is the very first information that ModSecurity can
     * inspect. It is expected to happens before the virtual host name be
     * resolved. This phase is expected to happen immediately after a
     * connection is established.
     *
     * 此阶段发生在链接刚刚建立之初，虚拟主机名还没有解析之前
     */
     ConnectionPhase,
    /**
     *
     * The "URI" phase happens just after the web server (or any other
     * application that you may use with ModSecurity) have the acknowledgement
     * of the full request URI.
     *
     * 当对应当服务器引擎已经拿到了全量当请求URI后，进行此阶段处理
     */
     UriPhase,
    /**
     *
     * The "RequestHeaders" phase happens when the server has all the
     * information about the headers. Notice however, that it is expected to
     * happen prior to the reception of the request body (if any).
     *
     * 当头部信息解析完毕后，请求体解析前
     */
     RequestHeadersPhase,
    /**
     *
     * At the "RequestHeaders" phase, ModSecurity is expected to inspect the
     * content of a request body, that does not happens when the server has all
     * the content but prior to that, when the body transmission started.
     * ModSecurity can ask the webserver to block (or make any other disruptive
     * action) while the client is still transmitting the data.
     *
     * 请求体开始传输时，进行流式检测处理；再‘处理请求头’阶段，有可能检测请
     * 求体，不过是在接收了所有的请求体之后才行
     */
     RequestBodyPhase,
    /**
     *
     * The "ResponseHeaders" happens just before all the response headers are
     * ready to be delivery to the client.
     *
     * 在所有当回应头准备发送给客户端前
     */
     ResponseHeadersPhase,
    /**
     *
     * Same as "RequestBody" the "ResponseBody" phase perform a stream
     * inspection which may result in a disruptive action.
     *
     * 流式检测，可能导致破坏性的动作行为
     */
     ResponseBodyPhase,
    /**
     *
     * The last phase is the logging phase. At this phase ModSecurity will
     * generate the internal logs, there is no need to hold the request at
     * this point as this phase does not produce any kind of action.
     *
     * 日志阶段，此后不必再保留请求
     */
     LoggingPhase,
    /**
     * Just a marking for the expected number of phases.
     * 
     * 处理阶段的结束标识
     */
     NUMBER_OF_PHASES,
    };

    /* 存储结构 */
    collection::Collection *m_global_collection;
    collection::Collection *m_resource_collection;
    collection::Collection *m_ip_collection;
    collection::Collection *m_session_collection;
    collection::Collection *m_user_collection;

 private:
    std::string m_connector;   /* connector，连接本库的适配器的简单说明，
                                  用于日志输出，便于分辨适配器 */
    LogCb m_logCb;
};


#endif

#ifdef __cplusplus
extern "C" {
#endif

/** @ingroup ModSecurity_C_API */
ModSecurity *msc_init();
/** @ingroup ModSecurity_C_API */
const char *msc_who_am_i(ModSecurity *msc);
/** @ingroup ModSecurity_C_API */
void msc_set_connector_info(ModSecurity *msc, const char *connector);
/** @ingroup ModSecurity_C_API */
void msc_set_log_cb(ModSecurity *msc, LogCb cb);
/** @ingroup ModSecurity_C_API */
void msc_cleanup(ModSecurity *msc);

#ifdef __cplusplus
}


}  // namespace modsecurity
#endif

#endif  // HEADERS_MODSECURITY_MODSECURITY_H_
