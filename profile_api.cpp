//
// Created by RGAA on 11/04/2025.
//

#include "profile_api.h"
#include "tc_common_new/http_client.h"
#include "tc_common_new/md5.h"
#include "tc_common_new/log.h"
#include "tc_3rdparty/json/json.hpp"

using namespace nlohmann;

namespace tc
{

    ///verify/device/info
    ProfileVerifyResult ProfileApi::VerifyDeviceInfo(const std::string& pr_srv_host,
                                                     int pr_srv_port,
                                                     const std::string& device_id,
                                                     const std::string& random_pwd_md5,
                                                     const std::string& safety_pwd_md5) {
        if (device_id.empty()) {
            return ProfileVerifyResult::kVfEmptyDeviceId;
        }
        if (pr_srv_host.empty() || pr_srv_port <= 0) {
            return ProfileVerifyResult::kVfEmptyServerHost;
        }
        auto client =
                HttpClient::MakeSSL(pr_srv_host, pr_srv_port, "/verify/device/info", 2000);
        auto resp = client->Request({
            {"device_id", device_id},
            {"random_pwd_md5", random_pwd_md5.empty() ? "" : random_pwd_md5},
            {"safety_pwd_md5", safety_pwd_md5.empty() ? "" : safety_pwd_md5},
        });
        if (resp.status != 200 || resp.body.empty()) {
            LOGE("Request new device failed.");
            return ProfileVerifyResult::kVfNetworkFailed;
        }

        try {
            //LOGI("Verify resp: {}", resp.body);
            auto obj = json::parse(resp.body);
            auto code = obj["code"].get<int>();
            if (code == kERR_PARAM_INVALID) {
                return ProfileVerifyResult::kVfParamInvalid;
            }
            else if (code == kERR_OPERATE_DB_FAILED) {
                return ProfileVerifyResult::kVfServerInternalError;
            }
            else if (code == kERR_DEVICE_NOT_FOUND) {
                return ProfileVerifyResult::kVfDeviceNotFound;
            }
            else if (code == kERR_PASSWORD_FAILED) {
                return ProfileVerifyResult::kVfPasswordFailed;
            }
            else if (code != 200) {
                return ProfileVerifyResult::kVfPasswordFailed;
            }

            auto data = obj["data"];
            auto resp_device_id = data["device_id"].get<std::string>();
            auto pwd_type = data["pwd_type"].get<std::string>();
            //LOGI("Verify device info result: {}==>{}", resp_device_id, pwd_type);
            if (pwd_type == "random") {
                return ProfileVerifyResult::kVfSuccessRandomPwd;
            }
            else if (pwd_type == "safety") {
                return ProfileVerifyResult::kVfSuccessSafetyPwd;
            }
            else if (pwd_type == "all") {
                return ProfileVerifyResult::kVfSuccessAllPwd;
            }
            else {
                return ProfileVerifyResult::kVfPasswordFailed;
            }
        } catch(...) {
            return ProfileVerifyResult::kVfParseJsonFailed;
        }
    }

}