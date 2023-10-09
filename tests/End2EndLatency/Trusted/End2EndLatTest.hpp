// Copyright (c) 2023 Haofan Zheng
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#pragma once


#include <cstdint>

#include <atomic>
#include <mutex>
#include <vector>
#include <stdexcept>
#include <condition_variable>

#include <AdvancedRlp/AdvancedRlp.hpp>

#include <DecentEnclave/Common/DecentTlsConfig.hpp>
#include <DecentEnclave/Common/Logging.hpp>
#include <DecentEnclave/Common/TlsSocket.hpp>

#include <DecentEnclave/Trusted/Time.hpp>
#include <DecentEnclave/Trusted/DecentLambdaClt.hpp>
#include <DecentEnclave/Trusted/ComponentConnection.hpp>
#include <DecentEnclave/Trusted/HeartbeatRecvMgr.hpp>
#include <DecentEnclave/Trusted/Sgx/Random.hpp>

#include <EclipseMonitor/Eth/AbiParser.hpp>

#include <SimpleObjects/Codec/Hex.hpp>


namespace End2EndLatency
{


inline std::vector<uint8_t> EventMsgFromReceiptData(
	const SimpleObjects::BytesBaseObj& receiptData
)
{
	std::vector<uint8_t> evMsg;

	using _MsgParser =
		EclipseMonitor::Eth::AbiParser<
			SimpleObjects::ObjCategory::Bytes,
			std::true_type
		>;
	auto abiBegin = receiptData.begin();
	auto abiEnd = receiptData.end();

	std::tie(evMsg, abiBegin) =
		_MsgParser().ToPrimitive(abiBegin, abiEnd, abiBegin);

	return evMsg;
}


inline uint64_t UIntFromReceiptData(
	const SimpleObjects::BytesBaseObj& receiptData
)
{
	uint64_t value = 0;

	using _AbiParserUint64 =
		EclipseMonitor::Eth::AbiParser<
			SimpleObjects::ObjCategory::Integer,
			EclipseMonitor::Eth::AbiUInt64
		>;
	auto abiBegin = receiptData.begin();
	auto abiEnd = receiptData.end();

	std::tie(value, abiBegin) =
		_AbiParserUint64().ToPrimitive(abiBegin, abiEnd, abiBegin);

	return value;
}


inline DecentEnclave::Common::DetMsg BuildPubSubSubscribeMsg(
	const EclipseMonitor::Eth::ContractAddr& publisherAddr
)
{
	static const SimpleObjects::String sk_labelPublisher("publisher");

	SimpleObjects::Dict msgContent;
	msgContent[sk_labelPublisher] = SimpleObjects::Bytes(
		publisherAddr.begin(),
		publisherAddr.end()
	);

	DecentEnclave::Common::DetMsg msg;
	//msg.get_Version() = 1;
	msg.get_MsgId().get_MsgType() = SimpleObjects::String("PubSub.Subscribe");
	msg.get_MsgContent() = SimpleObjects::Bytes(
		AdvancedRlp::GenericWriter::Write(msgContent)
	);

	return msg;
}


inline DecentEnclave::Common::DetMsg BuildRecSubscribeMsg(
	const EclipseMonitor::Eth::ContractAddr& publisherAddr
)
{
	static const SimpleObjects::String sk_labelContract("contract");
	static const SimpleObjects::String sk_labelTopics("topics");
	// static const SimpleObjects::Bytes  sk_subEventTopic(
	// 	std::vector<uint8_t>({
	// 		// 0x5745b04f0487ed3df77aef07f8203e42e3dda220117bb702fbb3fd48fb148d61
	// 		0x57U, 0x45U, 0xb0U, 0x4fU, 0x04U, 0x87U, 0xedU, 0x3dU,
	// 		0xf7U, 0x7aU, 0xefU, 0x07U, 0xf8U, 0x20U, 0x3eU, 0x42U,
	// 		0xe3U, 0xddU, 0xa2U, 0x20U, 0x11U, 0x7bU, 0xb7U, 0x02U,
	// 		0xfbU, 0xb3U, 0xfdU, 0x48U, 0xfbU, 0x14U, 0x8dU, 0x61U,
	// 	})
	// );
	static const SimpleObjects::Bytes  sk_subEventTopic(
		std::vector<uint8_t>({
			// 0xb7d6c1df015bd5e00161b18f26e9668ee858c58d0a2fdf5052390c06bf9d164b
			0xb7U, 0xd6U, 0xc1U, 0xdfU, 0x01U, 0x5bU, 0xd5U, 0xe0U,
			0x01U, 0x61U, 0xb1U, 0x8fU, 0x26U, 0xe9U, 0x66U, 0x8eU,
			0xe8U, 0x58U, 0xc5U, 0x8dU, 0x0aU, 0x2fU, 0xdfU, 0x50U,
			0x52U, 0x39U, 0x0cU, 0x06U, 0xbfU, 0x9dU, 0x16U, 0x4bU,
		})
	);


	SimpleObjects::Dict msgContent;
	msgContent[sk_labelContract] = SimpleObjects::Bytes(
		publisherAddr.begin(),
		publisherAddr.end()
	);
	msgContent[sk_labelTopics] = SimpleObjects::List({
		sk_subEventTopic,
	});

	DecentEnclave::Common::DetMsg msg;
	//msg.get_Version() = 1;
	msg.get_MsgId().get_MsgType() = SimpleObjects::String("Receipt.Subscribe");
	msg.get_MsgContent() = SimpleObjects::Bytes(
		AdvancedRlp::GenericWriter::Write(msgContent)
	);

	return msg;
}


inline void RunPubSubTest(
	const EclipseMonitor::Eth::ContractAddr& publisherAddr,
	const EclipseMonitor::Eth::ContractAddr& subscriberAddr
)
{
	using namespace DecentEnclave;

	static auto s_logger =
		Common::LoggerFactory::GetLogger("End2EndLatency::RunPubSubTest");

	std::vector<uint8_t> expectedValue(16);
	Trusted::Sgx::RandGenerator().Rand(expectedValue.data(), expectedValue.size());
	const SimpleObjects::Bytes expectedValueBytes(expectedValue);

	std::mutex timeMutex;
	std::condition_variable cv;
	std::atomic_uint64_t pubTime(0);
	std::atomic_uint64_t subsTime(0);

	auto pubsubCallback =
		[&pubTime, &cv, expectedValueBytes]
		(std::vector<uint8_t> heartbeatMsg) -> void
	{
		static auto s_cbLogger =
			Common::LoggerFactory::GetLogger("End2EndLatency::RunPubSubTest::pubsubCallback");

		s_cbLogger.Debug("Received heartbeat message");

		// 1. Get value from event
		auto msg = AdvancedRlp::Parse(heartbeatMsg);

		static const SimpleObjects::String sk_labelEvents("Events");

		const auto& msgDict = msg.AsDict();
		const auto& evQueue = msgDict[sk_labelEvents].AsList();

		s_cbLogger.Debug("Received " + std::to_string(evQueue.size()) + " events");
		if (evQueue.size() > 0)
		{
			const auto& evFields = evQueue[0].AsList();
			const auto& evData = evFields[1].AsBytes();

			// 2. Check if it is the expected value
			if (evData == expectedValueBytes)
			{
				// 3. If yes, record the time
				pubTime.store(DecentEnclave::Trusted::UntrustedTime::Timestamp());

				// 4. Notify the main thread
				cv.notify_one();
			}
		}
	};

	auto subsCallback =
		[&subsTime, &cv, expectedValue]
		(std::vector<uint8_t> heartbeatMsg) -> void
	{
		static auto s_cbLogger =
			Common::LoggerFactory::GetLogger("End2EndLatency::RunPubSubTest::subsCallback");

		s_cbLogger.Debug("Received heartbeat message");

		// 1. Get value from event
		auto msg = AdvancedRlp::Parse(heartbeatMsg);

		static const SimpleObjects::String sk_labelReceipts("Receipts");

		const auto& msgDict = msg.AsDict();
		const auto& recQueue = msgDict[sk_labelReceipts].AsList();

		s_cbLogger.Debug("Received " + std::to_string(recQueue.size()) + " receipts");
		if (recQueue.size() > 0)
		{
			const auto& recFields = recQueue[0].AsList();
			const auto& recData = recFields[2].AsBytes();
			// parse ABI encoding in receipt data
			auto confirmMsg = EventMsgFromReceiptData(recData);

			// 2. Check if it is the expected value
			if (confirmMsg == expectedValue)
			{
				// 3. If yes, record the time
				subsTime.store(DecentEnclave::Trusted::UntrustedTime::Timestamp());

				// 4. Notify the main thread
				cv.notify_one();
			}
		}
	};

	// 1. Subscribe to publisher
	s_logger.Info(
		"Subscribing to publisher @" +
			SimpleObjects::Codec::Hex::Encode<std::string>(publisherAddr)
	);
	auto subMsg = BuildPubSubSubscribeMsg(publisherAddr);
	std::shared_ptr<Common::TlsSocket> tlsSocket = Trusted::MakeLambdaCall(
		"DecentEthereum",
		Common::DecentTlsConfig::MakeTlsConfig(
			false,
			"Secp256r1",
			"Secp256r1"
		),
		subMsg // lvalue reference needed
	);
	std::shared_ptr<Trusted::HeartbeatTimeConstraint<uint64_t> > hbConstraint =
		std::make_shared<Trusted::HeartbeatTimeConstraint<uint64_t> >(
			1000
		);
	Trusted::HeartbeatRecvMgr::GetInstance().AddRecv(
		hbConstraint,
		tlsSocket,
		pubsubCallback,
		true
	);

	// 2. Subscribe to subscriber
	s_logger.Info(
		"Subscribing to subscriber @" +
			SimpleObjects::Codec::Hex::Encode<std::string>(subscriberAddr)
	);
	subMsg = BuildRecSubscribeMsg(subscriberAddr);
	tlsSocket = Trusted::MakeLambdaCall(
		"DecentEthereum",
		Common::DecentTlsConfig::MakeTlsConfig(
			false,
			"Secp256r1",
			"Secp256r1"
		),
		subMsg // lvalue reference needed
	);
	hbConstraint =
		std::make_shared<Trusted::HeartbeatTimeConstraint<uint64_t> >(
			1000
		);
	Trusted::HeartbeatRecvMgr::GetInstance().AddRecv(
		hbConstraint,
		tlsSocket,
		subsCallback,
		true
	);

	// 3. Record publish time
	uint64_t publishTime = DecentEnclave::Trusted::UntrustedTime::Timestamp();

	// 4. Publish message to publisher contract
	auto gethPxyCon = Trusted::ComponentConnection::Connect("gethProxy");
	std::string pxyMsg =
		"{\"method\": \"OraclePublish\", \"params\": [\""+
			SimpleObjects::Codec::Hex::Encode<std::string>(expectedValue) +
			"\"]}";
	gethPxyCon->SizedSendBytes(pxyMsg);

	// 5. Wait for results to be ready for collection
	std::unique_lock<std::mutex> lock(timeMutex);
	while (pubTime.load() == 0 || subsTime.load() == 0)
	{
		cv.wait(lock);
	}

	// 6. Gether results
	s_logger.Info("Published on:          " + std::to_string(publishTime));
	s_logger.Info("PubSub Notified on:    " + std::to_string(pubTime.load()));
	s_logger.Info("Subscriber Confirm on: " + std::to_string(subsTime.load()));
}


inline void MonitorAndReactTest()
{
	// auto oracleCallback = [] () {
	// 	// 1. Get value from event
	// 	// 2. Check if it is the expected value
	// 	// 3. If yes, record the time
	// 	// 4. Publish the same message to subscriber contract
	// };

	// auto subsCallback = [] () {
	// 	// 1. Get value from event
	// 	// 2. Check if it is the expected value
	// 	// 3. If yes, record the time
	// };

	// 1. Subscribe to publisher

	// 2. Record publish time

	// 3. Publish message to publisher contract

	// 4. Wait for results to be ready for collection

	// 5. Gether results
}


inline void RunTest(
	const EclipseMonitor::Eth::ContractAddr& pubsubAddr,
	const EclipseMonitor::Eth::ContractAddr& publisherAddr,
	const EclipseMonitor::Eth::ContractAddr& subscriberAddr
)
{
	(void)pubsubAddr;

	RunPubSubTest(publisherAddr, subscriberAddr);
}


} // namespace End2EndLatency
