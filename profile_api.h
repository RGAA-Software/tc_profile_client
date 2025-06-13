//
// Created by RGAA on 11/04/2025.
//

#ifndef GAMMARAY_PROFILE_API_H
#define GAMMARAY_PROFILE_API_H

#include <string>

namespace tc
{

    enum class ProfileVerifyResult {
        kVfParamInvalid,
        kVfServerInternalError,
        kVfDeviceNotFound,
        kVfEmptyDeviceId,
        kVfEmptyServerHost,
        kVfNetworkFailed,
        kVfResponseFailed,
        kVfParseJsonFailed,
        kVfSuccessRandomPwd,
        kVfSuccessSafetyPwd,
        kVfSuccessAllPwd,
        kVfPasswordFailed,
    };

    // HTTP CODE
    // see pr_error.rs
    constexpr int kERR_PARAM_INVALID = 600;
    constexpr int kERR_OPERATE_DB_FAILED = 601;
    constexpr int kERR_DEVICE_NOT_FOUND = 602;
    constexpr int kERR_PASSWORD_FAILED = 603;

    class ProfileApi {
    public:
        // verify device_id/random_pwd pair
        // pr_srv_host: profile server host
        // pr_srv_port: profile server port
        // device id
        // md5 random pwd
        // md5 safety pwd
        static ProfileVerifyResult VerifyDeviceInfo(const std::string& pr_srv_host,
                                                    int pr_srv_port,
                                                    const std::string& device_id,
                                                    const std::string& random_pwd_md5,
                                                    const std::string& safety_pwd_md5);
    };

}

#endif //GAMMARAY_PROFILE_API_H
