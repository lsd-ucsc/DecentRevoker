// Copyright (c) 2022 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <DecentEnclave/Common/Sgx/Exceptions.hpp>
#include <DecentEnclave/Untrusted/Sgx/DecentSgxEnclave.hpp>
#include <EclipseMonitor/Eth/DataTypes.hpp>


extern "C" sgx_status_t ecall_decent_revoker_init(
	sgx_enclave_id_t eid,
	sgx_status_t* retval,
	const uint8_t* pub_addr
);


namespace DecentRevoker
{


class DecentRevoker :
	public DecentEnclave::Untrusted::Sgx::DecentSgxEnclave
{
public: // static members:

	using Base = DecentEnclave::Untrusted::Sgx::DecentSgxEnclave;

public:

	DecentRevoker(
		const EclipseMonitor::Eth::ContractAddr& publisherAddr,
		const std::vector<uint8_t>& authList,
		const std::string& enclaveImgPath = DECENT_ENCLAVE_PLATFORM_SGX_IMAGE,
		const std::string& launchTokenPath = DECENT_ENCLAVE_PLATFORM_SGX_TOKEN
	) :
		Base(authList, enclaveImgPath, launchTokenPath)
	{
		DECENTENCLAVE_SGX_ECALL_CHECK_ERROR_E_R(
			ecall_decent_revoker_init,
			m_encId,
			publisherAddr.data()
		);
	}

	virtual ~DecentRevoker() = default;

private:

}; // class DecentRevoker


} // namespace DecentRevoker
