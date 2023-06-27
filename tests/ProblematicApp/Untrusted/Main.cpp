// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.


#include <memory>

#include <DecentEnclave/Common/Sgx/MbedTlsInit.hpp>
#include <DecentEnclave/Untrusted/Config/AuthList.hpp>
#include <DecentEnclave/Untrusted/Config/EndpointsMgr.hpp>
#include <SimpleJson/SimpleJson.hpp>
#include <SimpleSysIO/SysCall/Files.hpp>

#include "ProblematicApp.hpp"


using namespace DecentEnclave;
using namespace DecentEnclave::Common;
using namespace DecentEnclave::Untrusted;
using namespace ProblematicApp;
using namespace SimpleSysIO::SysCall;


int main(int argc, char* argv[]) {
	(void)argc;
	(void)argv;

	// Init MbedTLS
	Common::Sgx::MbedTlsInit::Init();


	// Read in components config
	auto configFile = RBinaryFile::Open(
		"../../../src/components_config.json"
	);
	auto configJson = configFile->ReadBytes<std::string>();
	auto config = SimpleJson::LoadStr(configJson);
	std::vector<uint8_t> authListAdvRlp = Config::ConfigToAuthListAdvRlp(config);


	// Endpoints Manager
	auto endpointMgr = Config::EndpointsMgr::GetInstancePtr(&config);


	// Create enclave
	auto enclave = std::make_shared<ProblematicApp::ProblematicApp>(
		authListAdvRlp
	);


	return 0;
}
