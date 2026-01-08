/* We simply call the root header file "App.h", giving you uWS::App and uWS::SSLApp */
#include "App.h"
#include "yyjson.h"
#include "hwss_manager.cc"
/* This is a simple WebSocket echo server example.
 * You may compile it with "WITH_OPENSSL=1 make" or with "make" */
static const std::string groupClient = "client";
static const std::string groupAdmin = "admin";
static const char *HTTP_400_OK = "400 OK";

#define hwssIsDebug   true


int main() {
    /* ws->getUserData returns one of these */
    struct PerSocketData {
        /* Fill with user data */
        bool roleAdmin;
        bool hasAuth;
        const std::string appId;
        const int64_t connId;
    };


    /* Keep in mind that uWS::SSLApp({options}) is the same as uWS::App() when compiled without SSL support.
     * You may swap to using uWS:App() if you don't need SSL */
    uWS::SSLApp({
        /* There are example certificates in uWebSockets.js repo */
	    .key_file_name = "/Users/efurture/hwss/hwss/tool/example.com-key.pem",
	    .cert_file_name = "/Users/efurture/hwss/hwss/tool/example.com.pem",
	    .passphrase = ""
	}).ws<PerSocketData>("/*", {
        /* Settings */
        .compression = uWS::CompressOptions(uWS::DEDICATED_COMPRESSOR_4KB | uWS::DEDICATED_DECOMPRESSOR),
        .maxPayloadLength = 16 * 1024,
        .idleTimeout = 120,
        .maxBackpressure = 4 * 1024 * 1024,
        .closeOnBackpressureLimit = false,
        .resetIdleTimeoutOnSend = false,
        .sendPingsAutomatically = true,
        /* Handlers */
        .upgrade = [](uWS::HttpResponse<true> *res, uWS::HttpRequest* req, auto *context) {
            std::cout<<  res->getRemoteAddressAsText()  << " url " << req->getFullUrl() << " url " << req->getUrl() << " " << std::endl;
            auto appId = req->getQuery("app_id");
            auto appToken = req->getQuery("app_token");
            auto group = req->getQuery("group");
            auto fmt = req->getQuery("fmt");
            if (hwssIsDebug) {
               std::cout << "group " << group << "app_id " << appId << "app_token" << appToken << group << std::endl;
            }
            if (!(group == groupAdmin || group == groupClient)) {
                if (hwssIsDebug) {
                    std::cout << "missing group parameter, please pass group=client or group=admin parameter: " << group << std::endl;
                }
                res->writeStatus("400 Bad Request missing group parameter, please pass group=client or group=admin parameter");
                res->end("", true);
                return;
            }
            if (appId.length() < 1) {
                 if (hwssIsDebug) {
                    std::cout << "missing app_id parameter, please pass like app_id=test" << std::endl;
                }
                res->writeStatus("400 Bad Request missing app_id parameter, please pass like app_id=test");
                res->end("", true);
                return;
            }
            if (group == groupClient) {
                if (hwssIsDebug) {
                    std::cout << "app_id " << appId << " upgrade success" << std::endl;
                }
                res->template upgrade<PerSocketData>({
                                /* We initialize PerSocketData struct here */
                                .appId = std::string(appId),
                                .connId = hwss::nextConnId(),
                                .roleAdmin = false,
                                .hasAuth = false
                            }, req->getHeader("sec-websocket-key"),
                                req->getHeader("sec-websocket-protocol"),
                                req->getHeader("sec-websocket-extensions"),
                                context);
                 return;                   
            }
            //handle for group admin
            if (appToken.length() < 1) {
                if (hwssIsDebug) {
                    std::cout << "missing app_token parameter, please pass like app_toke=test" << std::endl;
                }
                res->writeStatus("400 Bad Request missing app_token parameter, please pass like app_token=test");
                res->end("", true);
                return;
            }

            //FIXME CHECK PERMISSION
    
            /* You may read from req only here, and COPY whatever you need into your PerSocketData.
             * PerSocketData is valid from .open to .close event, accessed with ws->getUserData().
             * HttpRequest (req) is ONLY valid in this very callback, so any data you will need later
             * has to be COPIED into PerSocketData here. */

            /* Immediately upgrading without doing anything "async" before, is simple */
        
            res->template upgrade<PerSocketData>({
                /* We initialize PerSocketData struct here */
                .appId = std::string(appId),
                .connId = hwss::nextConnId(),
                .roleAdmin = true,
                .hasAuth = false
            }, req->getHeader("sec-websocket-key"),
                req->getHeader("sec-websocket-protocol"),
                req->getHeader("sec-websocket-extensions"),
                context);

            /* If you don't want to upgrade you can instead respond with custom HTTP here,
             * such as res->writeStatus(...)->writeHeader(...)->end(...); or similar.*/

            /* Performing async upgrade, such as checking with a database is a little more complex;
             * see UpgradeAsync example instead. */
        },
        .open = [](auto *ws) {
            /* Open event here, you may access ws->getUserData() which points to a PerSocketData struct */
            const PerSocketData* perSocketData = ws->getUserData();
            std::shared_ptr<hwss::Manager> manager = hwss::manager;
            int64_t connId = perSocketData->connId;
            if (manager->connIdClients[connId] != nullptr) {
                if (hwssIsDebug) {
                    std::cout << "error connId repeat " << connId << std::endl;
                }
            }
            manager->connIdClients[connId] = ws;

        },
        .message = [](auto *ws, std::string_view message, uWS::OpCode opCode) {
            const PerSocketData* perSocketData = ws->getUserData();
            if (perSocketData->roleAdmin) {
                 //handle redirect message to client
            } else {
                //redirct message to admin if has auther;
                if (perSocketData->hasAuth) {

                } else {

                }
            }
            /* This is the opposite of what you probably want; compress if message is LARGER than 16 kb
             * the reason we do the opposite here; compress if SMALLER than 16 kb is to allow for 
             * benchmarking of large message sending without compression */
            ws->send(message, opCode, message.length() < 16 * 1024);

            ws->end(0, "hello world");
        },
        .dropped = [](auto */*ws*/, std::string_view /*message*/, uWS::OpCode /*opCode*/) {
            /* A message was dropped due to set maxBackpressure and closeOnBackpressureLimit limit */
        },
        .drain = [](auto */*ws*/) {
            /* Check ws->getBufferedAmount() here */
        },
        .close = [](auto *ws, int /*code*/, std::string_view /*message*/) {
            /* You may access ws->getUserData() here */
           const PerSocketData* perSocketData = ws->getUserData();
           const int64_t connId = perSocketData->connId;
           std::shared_ptr<hwss::Manager> manager = hwss::manager;
           manager->connIdClients.erase(connId);
           if (hwssIsDebug) {
                std::cout << "close connection connId " << connId << " connections " << manager->connIdClients.size() << std::endl;
            }
            // https://developer.mozilla.org/en-US/docs/Web/API/CloseEvent/code
        }
    }).listen(9001, [](auto *listen_socket) {
        if (listen_socket) {
            std::cout << "Listening on port " << 9001 << std::endl;
        }
    }).run();
}
