#!/usr/bin/env python3
# -*- coding:utf-8 -*-
###
# Copyright (c) 2023 Haofan Zheng
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
###


import json
import logging
import os
import signal
import socket
import socketserver
import subprocess
import time

from web3 import Web3
from web3.contract.contract import Contract
from typing import Tuple, Union

from PyEthHelper import EthContractHelper, GanacheAccounts


HOST_ADDR = 'localhost'
HOST_PORT = 51234

USE_GANACHE = True
KEY_FILE_PATH = '/home/public/ndss-ae/decent_keys.json'
GETH_ADDR     = 'localhost'
GETH_PORT     = 8546

THIS_DIR  = os.path.dirname(os.path.abspath(__file__))
TARGET_DIR = os.path.abspath(os.path.join(THIS_DIR, '..'))
BUILD_DIR = os.path.join(THIS_DIR, 'build')
REPO_DIR = os.path.abspath(os.path.join(TARGET_DIR, '..', '..'))
PUBSUB_REPO_DIR = os.path.abspath(os.path.join(REPO_DIR, '..', 'decent-pubsub-onchain'))
PUBSUB_BUILD_DIR = os.path.join(PUBSUB_REPO_DIR, 'build')

SUBS_CONTRACT_BASE_PATH = os.path.join(BUILD_DIR, 'HybridSubscriber')
ORAC_CONTRACT_BASE_PATH = os.path.join(BUILD_DIR, 'Oracle')
PUBS_CONTRACT_BASE_PATH = os.path.join(PUBSUB_BUILD_DIR, 'PubSub', 'PubSubService')
CONF_FILE_PATH = os.path.join(TARGET_DIR, 'components_config.json')


class GethProxy(object):

	@classmethod
	def LoadContracts(cls, w3: Web3) -> Tuple[Contract, Contract]:
		if USE_GANACHE:
			pubsubContract = EthContractHelper.LoadContract(
				w3=w3,
				projConf=(
					PUBS_CONTRACT_BASE_PATH + '.abi',
					PUBS_CONTRACT_BASE_PATH + '.bin',
				),
				contractName='PubSubService',
				release=None, # use locally built contract
				address=None, # deploy new contract
			)
		else:
			pubsubContract = None

		oracleContract = EthContractHelper.LoadContract(
			w3=w3,
			projConf=(
				ORAC_CONTRACT_BASE_PATH + '.abi',
				ORAC_CONTRACT_BASE_PATH + '.bin',
			),
			contractName='Oracle',
			release=None, # use locally built contract
			address=None, # deploy new contract
		)
		subscriberContract = EthContractHelper.LoadContract(
			w3=w3,
			projConf=(
				SUBS_CONTRACT_BASE_PATH + '.abi',
				SUBS_CONTRACT_BASE_PATH + '.bin',
			),
			contractName='HybridSubscriber',
			release=None, # use locally built contract
			address=None, # deploy new contract
		)
		return oracleContract, subscriberContract, pubsubContract

	@classmethod
	def DeployContracts(
		cls,
		w3: Web3,
		privKey: str,
		pubSub: Union[str, Contract],
		oracleContract: Contract,
		subscriberContract: Contract,
	) -> Tuple[Contract, Contract, Contract]:
		if isinstance(pubSub, str):
			pubSubAddr = pubSub
		else:
			deployReceipt = EthContractHelper.DeployContract(
				w3=w3,
				contract=pubSub,
				arguments=[ ],
				privKey=privKey,
				gas=None, # let web3 estimate
				value=0,
				confirmPrompt=False # don't prompt for confirmation
			)
			pubSubAddr = deployReceipt.contractAddress
			pubSub = EthContractHelper.LoadContract(
				w3=w3,
				projConf=(
					PUBS_CONTRACT_BASE_PATH + '.abi',
					PUBS_CONTRACT_BASE_PATH + '.bin',
				),
				contractName='PubSubService',
				release=None, # use locally built contract
				address=pubSubAddr,
			)

		# deploy and register the oracle contract
		deployReceipt = EthContractHelper.DeployContract(
			w3=w3,
			contract=oracleContract,
			arguments=[ pubSubAddr, ],
			privKey=privKey,
			gas=None, # let web3 estimate
			value=0,
			confirmPrompt=False # don't prompt for confirmation
		)
		oracleContract = EthContractHelper.LoadContract(
			w3=w3,
			projConf=(
				ORAC_CONTRACT_BASE_PATH + '.abi',
				ORAC_CONTRACT_BASE_PATH + '.bin',
			),
			contractName='Oracle',
			release=None, # use locally built contract
			address=deployReceipt.contractAddress,
		)

		# deploy and subscribe the subscriber contract
		deployReceipt = EthContractHelper.DeployContract(
			w3=w3,
			contract=subscriberContract,
			arguments=[ pubSubAddr, oracleContract.address, ],
			privKey=privKey,
			gas=None, # let web3 estimate
			value=w3.to_wei(0.001, 'ether'),
			confirmPrompt=False # don't prompt for confirmation
		)
		subscriberContract = EthContractHelper.LoadContract(
			w3=w3,
			projConf=(
				SUBS_CONTRACT_BASE_PATH + '.abi',
				SUBS_CONTRACT_BASE_PATH + '.bin',
			),
			contractName='HybridSubscriber',
			release=None, # use locally built contract
			address=deployReceipt.contractAddress,
		)

		return oracleContract, subscriberContract, pubSub

	@classmethod
	def GetEventMgrAddr(cls, w3: Web3, contract: Contract) -> str:
		# get the address of the event manager
		eventMgrAddr = contract.functions.m_eventMangerAddr().call()
		return eventMgrAddr

	def __init__(
		self,
		w3: Web3,
		privKey: str,
		pubSubAddr: str,
	) -> None:
		super(GethProxy, self).__init__()

		self.logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

		self.w3 = w3
		self.privKey = privKey

		(
			self.oracleContract,
			self.subscriberContract,
			self.pubsubContract,
		) = self.LoadContracts(
			w3=self.w3,
		)
		self.logger.info('Contracts loaded')

		_pubsub = pubSubAddr if self.pubsubContract is None else self.pubsubContract
		(
			self.oracleContract,
			self.subscriberContract,
			self.pubsubContract,
		) = self.DeployContracts(
			w3=self.w3,
			privKey=self.privKey,
			pubSub=_pubsub,
			oracleContract=self.oracleContract,
			subscriberContract=self.subscriberContract,
		)
		self.logger.info(
			'Oracle contract deployed at {}'.format(self.oracleContract.address)
		)
		self.logger.info(
			'Subscriber contract deployed at {}'.format(self.subscriberContract.address)
		)

		_eventMgrAddr = self.GetEventMgrAddr(
			w3=self.w3,
			contract=self.oracleContract,
		)
		self.logger.info(
			'Event manager address: {}'.format(_eventMgrAddr)
		)

	def PublishData(self, data: bytes) -> None:
		receipt = EthContractHelper.CallContractFunc(
			w3=self.w3,
			contract=self.oracleContract,
			funcName='onDataAvailable',
			arguments=[ data, ],
			privKey=self.privKey,
			confirmPrompt=False, # don't prompt for confirmation
			gas=None,
		)

	def TransactData(self, data: bytes) -> None:
		receipt = EthContractHelper.CallContractFunc(
			w3=self.w3,
			contract=self.subscriberContract,
			funcName='onTransaction',
			arguments=[ data, ],
			privKey=self.privKey,
			confirmPrompt=False, # don't prompt for confirmation
			gas=None,
		)


def GethProxyTCPHandler(proxyCore: GethProxy) -> type:
	class TCPHandlerTemplate(socketserver.BaseRequestHandler):

		PROXY_CORE = proxyCore

		def OraclePublish(self, dataHex: str) -> dict:
			if dataHex.startswith('0x'):
				dataHex = dataHex[2:]

			data = bytes.fromhex(dataHex)
			self.PROXY_CORE.PublishData(data=data)

			return {
				'status': 'ok',
				'result': [],
			}

		def SubscriberTransact(self, dataHex: str) -> dict:
			if dataHex.startswith('0x'):
				dataHex = dataHex[2:]

			data = bytes.fromhex(dataHex)
			self.PROXY_CORE.TransactData(data=data)

			return {
				'status': 'ok',
				'result': [],
			}

		def UnknownMethod(self, method: str) -> dict:
			return {
				'status': 'error',
				'result': 'Unknown method: {}'.format(method),
			}

		def handleRequest(self, requestJson: dict) -> dict:
			method = requestJson['method']
			params = requestJson['params']
			if method == 'OraclePublish':
				return self.OraclePublish(*params)
			elif method == 'SubscriberTransact':
				return self.SubscriberTransact(*params)
			else:
				return self.UnknownMethod(method)

		def ConnectionClosing(
			self,
			client: tuple,
			e: Union[Exception, None]
		) -> None:
			if e is None:
				self.PROXY_CORE.logger.info(
					'{}: Connection closed by the client'.format(client)
				)
			else:
				self.PROXY_CORE.logger.info(
					'{}: Exception {}. Closing the socket'.format(client, e)
				)
				# self.PROXY_CORE.logger.exception(e)

		def handle(self):
			self.PROXY_CORE.logger.info('{}: New connection'.format(self.client_address))

			sock: socket.socket = self.request
			while True:
				try:
					# recv 64bit data length
					rawSockData = sock.recv(8)
					if len(rawSockData) == 0:
						self.ConnectionClosing(client=self.client_address, e=None)
						return
					dataLen = int.from_bytes(rawSockData, byteorder='little')
					# recv data
					rawSockData = sock.recv(dataLen)
					if len(rawSockData) == 0:
						self.ConnectionClosing(client=self.client_address, e=None)
						return

					requestJson = json.loads(rawSockData)
					responseJson = self.handleRequest(requestJson)
					responseData = json.dumps(responseJson).encode('utf-8')
					self.PROXY_CORE.logger.info('Response: {}'.format(responseData))

					# send 64bit data length
					sock.sendall(len(responseData).to_bytes(8, byteorder='little'))
					# send data
					sock.sendall(responseData)
				except Exception as e:
					self.ConnectionClosing(client=self.client_address, e=e)
					return

	return TCPHandlerTemplate


def StartGanache() -> subprocess.Popen:
	if not USE_GANACHE:
		# we are using the actual Geth Client, so do nothing
		return None

	global GETH_ADDR, GETH_PORT, GANACHE_KEY_PATH, KEY_FILE_PATH
	GETH_ADDR = 'localhost'
	GETH_PORT = 7545
	GANACHE_KEY_PATH = os.path.join(BUILD_DIR, 'ganache_keys.json')
	KEY_FILE_PATH = os.path.join(BUILD_DIR, 'ganache_ckeys.json')

	_NUM_KEYS = 10
	_NET_ID = 1337
	_NODE_PATH = '/snap/bin/node'
	_GANACHE_PATH = '/usr/local/bin/ganache-cli'

	cmd = [
		_NODE_PATH,
		_GANACHE_PATH,
		'-p', str(GETH_PORT),
		'-d',
		'-a', str(_NUM_KEYS),
		'--network-id', str(_NET_ID),
		'--chain.hardfork', 'shanghai',
		'--wallet.accountKeysPath', str(GANACHE_KEY_PATH),
	]
	proc = subprocess.Popen(
		cmd,
		stdout=subprocess.PIPE,
		stderr=subprocess.PIPE
	)

	return proc


def SetupPrivKey(w3: Web3) -> str:
	if USE_GANACHE:
		GanacheAccounts.ChecksumGanacheKeysFile(
			KEY_FILE_PATH,
			GANACHE_KEY_PATH
		)

	# setup account
	privKey = EthContractHelper.SetupSendingAccount(
		w3=w3,
		account=0, # use account 0
		keyJson=KEY_FILE_PATH
	)

	return privKey


def StopGanache(ganacheProc: subprocess.Popen) -> None:
	if not USE_GANACHE:
		# we are using the actual Geth Client, so do nothing
		return

	print('Shutting down ganache (it may take ~15 seconds)...')
	waitEnd = time.time() + 20
	ganacheProc.terminate()
	while ganacheProc.poll() is None:
		try:
			if time.time() > waitEnd:
				print('Force to shut down ganache')
				ganacheProc.kill()
			else:
				print('Still waiting for ganache to shut down...')
				ganacheProc.send_signal(signal.SIGINT)
			ganacheProc.wait(timeout=2)
		except subprocess.TimeoutExpired:
			continue

	logger = logging.getLogger('ganache-cli')
	for line in ganacheProc.stdout:
		logger.debug(line.decode('utf-8', errors='ignore').strip())
	for line in ganacheProc.stderr:
		logger.error(line.decode('utf-8', errors='ignore').strip())
	print('Ganache has been shut down')


def main():
	logging.basicConfig(
		level=logging.INFO,
		format='[%(asctime)s](%(levelname)s) %(name)s: %(message)s'
	)
	logger = logging.getLogger(__name__ + '.' + main.__name__)

	# load configure
	with open(CONF_FILE_PATH, 'r') as f:
		conf = json.load(f)
	pubSubAddr = '0x' + conf['PubSub']['PubSubAddr']

	# start Ganache if necessary
	ganacheProc = StartGanache()

	try:
		# connect to Geth Client
		gethUrl = 'http://{}:{}'.format(GETH_ADDR, GETH_PORT)
		logger.info('Connecting to Geth Client at {}'.format(gethUrl))
		w3 = Web3(Web3.HTTPProvider(gethUrl))
		while not w3.is_connected():
			logger.debug('Attempting to connect to Geth Client...')
			time.sleep(1)
		logger.info('Connected to Geth Client')

		# setup account
		privKey = SetupPrivKey(w3=w3)

		gethProxy = GethProxy(
			w3=w3,
			privKey=privKey,
			pubSubAddr=pubSubAddr,
		)
		# gethProxy.PublishData(data=b'Hello World!')
		# gethProxy.TransactData(data=b'Hello World!')

		# start TCP server
		handlerCls = GethProxyTCPHandler(gethProxy)
		with socketserver.TCPServer((HOST_ADDR, HOST_PORT), handlerCls) as server:
			server.serve_forever()

	finally:
		# finish and exit
		StopGanache(ganacheProc)
		pass


if __name__ == '__main__':
	main()

