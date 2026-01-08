#include <limits>
#include <cstdint>
#include <map>
#include <vector>

#include <yyjson.h>

namespace hwss {
    class Manager{
        public : 
           Manager() {

           }
        public :
        std::unordered_map<int64_t,void*> connIdClients;
        std::unordered_map<std::string, std::shared_ptr<std::vector<void*>>> groupAdmins;
    };

    static std::shared_ptr<hwss::Manager> manager = std::make_shared<hwss::Manager>();
    static int64_t  connId = 0;

    int64_t nextConnId() {
        return connId++;
    }

    std::string authMsg(const std::string_view& message) {
        
    }

}