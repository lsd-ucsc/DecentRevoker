// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.


#include <memory>

#include <DecentEnclave/Common/Platform/Print.hpp>
#include <DecentEnclave/Common/Sgx/MbedTlsInit.hpp>
#include <DecentEnclave/Untrusted/Config/AuthList.hpp>
#include <DecentEnclave/Untrusted/Config/EndpointsMgr.hpp>
#include <DecentEnclave/Untrusted/Hosting/BoostAsioService.hpp>
#include <SimpleConcurrency/Threading/ThreadPool.hpp>
#include <SimpleJson/SimpleJson.hpp>
#include <SimpleObjects/Internal/make_unique.hpp>
#include <SimpleSysIO/SysCall/Files.hpp>

#include "DecentRevoker.hpp"
#include "RunUntilSignal.hpp"


using namespace DecentEnclave;
using namespace DecentEnclave::Common;
using namespace DecentEnclave::Untrusted;
using namespace DecentRevoker;
using namespace SimpleConcurrency::Threading;
using namespace SimpleSysIO::SysCall;


int main(int argc, char* argv[]) {
	(void)argc;
	(void)argv;

	// Init MbedTLS
	Common::Sgx::MbedTlsInit::Init();


	// Read in components config
	auto configFile = RBinaryFile::Open(
		"../../src/components_config.json"
	);
	auto configJson = configFile->ReadBytes<std::string>();
	auto config = SimpleJson::LoadStr(configJson);
	std::vector<uint8_t> authListAdvRlp = Config::ConfigToAuthListAdvRlp(config);


	// Thread pool
	std::shared_ptr<ThreadPool> threadPool = std::make_shared<ThreadPool>(5);


	// Boost IO Service
	std::unique_ptr<Hosting::BoostAsioService> asioService =
		SimpleObjects::Internal::make_unique<Hosting::BoostAsioService>();
	auto asioIoService = asioService->GetIoService();
	threadPool->AddTask(std::move(asioService));


	// Endpoints Manager
	auto endpointMgr = Config::EndpointsMgr::GetInstancePtr(
		&config,
		asioIoService
	);


	// Create enclave
	auto enclave = std::make_shared<DecentRevoker::DecentRevoker>(
		authListAdvRlp
	);


	RunUntilSignal(
		[&]()
		{
			threadPool->Update();
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}
	);


	threadPool->Terminate();


	return 0;
}
