#!/usr/bin/env

import requests
import json
import base64
import os

def run_methods(file, url, methods, method_type, perms):

    print("-"*50)
    print("-"*50)
    print("-"*50)
    print("\nRunning " + method_type + " Methods\n")
    print("-"*50)
    print("-"*50)
    print("-"*50 + "\n")

    for method in methods:
        print("="*50)
        print("Testing " + method + ": " + str(methods[method]))
        print("="*50)
        file.write("="*100 + "\n")
        file.write("Testing " + method + ": " + str(methods[method]) + "\n")
        file.write("="*100 + "\n\n")
        for token, perm in perms:
            headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + token,
            }
            function = "Filecoin." + method
            params = methods[method]
            data = {
                "jsonrpc": "2.0",
                "method": function,
                "params": params,
                "id": 0
            }
            response = requests.post(url, headers=headers, json=data)
            print(str(response.text) + "\n\n")
            if "missing permission" in str(response.text) and "200" in str(response):
                file.write(perm + " token unable to call the api method " + method + "\n")
                file.write(str(response.text))
                file.write(json.dumps(data) + "\n\n")
            else:
                file.write(perm + " token was able to successfully call the api method " + method + "\n")
                file.write(str(response.text) + "\n\n")

if __name__=="__main__":

    os.system("lotus auth create-token --perm read > ~/.lotus/read")
    os.system("lotus auth create-token --perm write > ~/.lotus/write")
    os.system("lotus auth create-token --perm sign > ~/.lotus/sign")
    os.system("lotus-storage-miner auth create-token --perm read > ~/.lotusstorage/read")
    os.system("lotus-storage-miner auth create-token --perm read > ~/.lotusstorage/write")
    os.system("lotus-storage-miner auth create-token --perm read > ~/.lotusstorage/sign")

    lotusPerms = [
        (open(os.path.expanduser("~/.lotus/read"), "r").read().strip("\n"), "read"),
        (open(os.path.expanduser("~/.lotus/write"), "r").read().strip("\n"), "write"),
        (open(os.path.expanduser("~/.lotus/sign"), "r").read().strip("\n"), "sign"),
        (open(os.path.expanduser("~/.lotus/token"), "r").read(), "admin")
    ]

    lotusStoragePerms = [
        (open(os.path.expanduser("~/.lotusstorage/read"), "r").read().strip("\n"), "read"),
        (open(os.path.expanduser("~/.lotusstorage/write"), "r").read().strip("\n"), "write"),
        (open(os.path.expanduser("~/.lotusstorage/sign"), "r").read().strip("\n"), "sign"),
        (open(os.path.expanduser("~/.lotusstorage/token"), "r").read(), "admin")
    ]

    lotusOutput = open(os.path.expanduser("~/lotus-review/tests/lotusAPIOutput"), "w")
    storageMinerOutput = open(os.path.expanduser("~/lotus-review/tests/storageMinerAPIOutput"), "w")
    sealWorkerOutput = open(os.path.expanduser("~/lotus-review/tests/sealWorkerAPIOutput"), "w")

    address = "t3qcmxscntgxzwpkzodifg6kzopwou4h4mccgyaxjxdcoh6cxrz67rb2moy22ssma4mnhvoeeqvkpotvmjxauq"
    actorAddress = "t01000"
    peerID = "12D3KooWN7X2zSAmFS3UDrr4gZS9K6GbgWgmdbRNRSZXUvr1C5kZ"
    peerAddrInfo = {"Addrs":["/ip4/147.75.67.199/tcp/4001"],"ID":"QmTd6UvR47vUidRNZ1ZKXHrAFhqTJAD27rKL9XYghEKgKX"}
    randomBytes = base64.b64encode(b"This is a string").decode("utf-8")

    fullNodeMethods = {
        "ChainNotify": [],
        "ChainHead": [],
        "ChainGetRandomness": [None, None, None, randomBytes],
        "ChainGetBlock": [None],
        "ChainGetTipSet": [None],
        "ChainGetBlockMessages": [None],
        "ChainGetParentReceipts": [None],
        "ChainGetParentMessages": [None],
        "ChainGetTipSetByHeight": [None, None],
        "ChainReadObj": [None],
        "ChainHasObj": [None],
        # "ChainStatObj": [None, None], ### Causes Crash
        "ChainSetHead": [None],
        "ChainGetGenesis": [],
        "ChainTipSetWeight": [None],
        "ChainGetNode": [None],
        "ChainGetMessage": [None],
        "ChainGetPath": [None, None],
        "ChainExport": [None],
        "SyncState": [],
        "SyncSubmitBlock": [None],
        "SyncIncomingBlocks": [],
        "SyncMarkBad": [None],
        "SyncCheckBad": [None],
        "MpoolPending": [None],
        "MpoolPush": [None],
        "MpoolPushMessage": [None],
        "MpoolGetNonce": [address],
        "MpoolSub": [],
        "MpoolEstimateGasPrice": [10, address, 15, None],
        "MinerGetBaseInfo": [address, None, None],
        "MinerCreateBlock": [None],
        "WalletNew": [None],
        "WalletHas": [address],
        "WalletList": [],
        "WalletBalance": [address],
        "WalletSign": [address, randomBytes],
        "WalletSignMessage": [address, None],
        "WalletVerify": [address, randomBytes, None],
        "WalletDefaultAddress": [],
        "WalletSetDefault": [address],
        "WalletExport": [address],
        "WalletImport": [None],
        "ClientImport": [None],
        "ClientListImports": [],
        "ClientHasLocal": [None],
        "ClientFindData": [None],
        "ClientStartDeal": [None],
        "ClientGetDealInfo": [None],
        "ClientListDeals": [],
        "ClientRetrieve": [None, None],
        "ClientQueryAsk": [peerID, address],
        "ClientCalcCommP": [None, None],
        "ClientGenCar": [None, None],
        "StateNetworkName": [],
        "StateMinerSectors": [address, None, False, None],
        "StateMinerProvingSet": [address, None],
        "StateMinerProvingDeadline": [address, None],
        "StateMinerPower": [address, None],
        "StateMinerInfo": [address, None],
        "StateMinerDeadlines": [address, None],
        "StateMinerFaults": [address, None],
        "StateAllMinerFaults": [None, None],
        "StateMinerRecoveries": [address, None],
        "StateMinerInitialPledgeCollateral": [address, None, None],
        "StateMinerAvailableBalance": [address, None],
        "StateSectorPreCommitInfo": [address, None, None],
        "StateCall": [None, None],
        "StateReplay": [None, None],
        "StateGetActor": [address, None],
        "StateReadState": [None, None],
        "StatePledgeCollateral": [None],
        "StateWaitMsg": [None],
        "StateSearchMsg": [None],
        "StateListMiners": [None],
        "StateListActors": [None],
        "StateMarketBalance": [address, None],
        "StateMarketParticipants": [None],
        "StateMarketDeals": [None],
        "StateMarketStorageDeal": [None, None],
        "StateLookupID": [address, None],
        "StateAccountKey": [address, None],
        "StateChangedActors": [None, None],
        "StateGetReceipt": [None, None],
        "StateMinerSectorCount": [address, None],
        "StateListMessages": [None, None, None],
        "StateCompute": [None, None, None],
        "MsigGetAvailableBalance": [address, None],
        "MsigCreate": [None, None, "0", None, "0"],
        "MsigPropose": [None, None, "0", None, None, randomBytes],
        "MsigApprove": [None, None, None, None, "0", None, None, randomBytes],
        "MsigCancel": [None, None, None, None, "0", None, None, randomBytes],
        "MarketEnsureAvailable": [None, None, "0"],
        "PaychGet": [None, None, "0"],
        "PaychList": [],
        "PaychStatus": [address],
        "PaychClose": [address],
        "PaychAllocateLane": [address],
        "PaychNewPayment": [None, None, None],
        "PaychVoucherCheck": [None],
        "PaychVoucherCheckValid": [address, None],
        "PaychVoucherCheckSpendable": [address, None, randomBytes, randomBytes],
        "PaychVoucherAdd": [address, None, randomBytes, "0"],
        "PaychVoucherCreate": [address, "5", 10],
        "PaychVoucherList": [address],
        "PaychVoucherSubmit": [address, None],
        # "AuthVerify": ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBbGxvdyI6WyJyZWFkIiwid3JpdGUiLCJzaWduIiwiYWRtaW4iXX0.j1DG_DrxH85bOAk1GJh-gZ5H_71UB1qswiiha-bDEj0"], ### Should fail when verifying a token with a different signature.
        "AuthVerify": [open(os.path.expanduser("~/.lotus/token"), "r").read()],
        "AuthNew": [None],
        "NetConnectedness": [peerID],
        "NetPeers": [],
        "NetConnect": [peerAddrInfo],
        "NetAddrsListen": [],
        "NetDisconnect": [peerID],
        "NetFindPeer": [peerID],
        "ID": [],
        "Version": [],
        "LogList": [],
        "LogSetLevel": ["*", "Debug"],
        # "Shutdown": [], ### Shuts down Lotus daemon
    }
    storageNodeMethods = {
        "ActorAddress": [],
        "ActorSectorSize": [actorAddress],
        "MiningBase": [],
        "MarketImportDealData": [None, randomBytes],
        "MarketListDeals": [],
        "MarketListIncompleteDeals": [],
        "MarketSetPrice": ["10"],
        "PledgeSector": [],
        "SectorsStatus": [None],
        "SectorsList": [],
        "SectorsRefs": [],
        "SectorsUpdate": [None, None],
        "WorkerConnect": [randomBytes],
        "WorkerStats": [],
        "StorageList": [],
        "StorageLocal": [],
        "StorageStat": [None],
        "StorageAttach": [None, None],
        "StorageDeclareSector": [None, None, None],
        "StorageDropSector": [None, None, None],
        "StorageFindSector": [None, None, True],
        "StorageInfo": [None],
        "StorageBestAlloc": [None, None, True],
        "StorageReportHealth": [None, None],
        "DealsImportData": [None, randomBytes],
        "DealsList": [],
        "StorageAddLocal": [randomBytes],
    }

    workerNodeMethods = {
        "Version": [],
        "TaskTypes": [],
        "Paths": [],
        "Info": [],
        "SealPreCommit1": [None, None, None],
        "SealPreCommit2": [None, None],
        "SealCommit1": [None, None, None, None, None],
        "SealCommit2": [None, None],
        "FinalizeSector": [None],
        "Fetch": [None, None, True],
        "Closing": [],
    }

    run_methods(lotusOutput, "http://127.0.0.1:1234/rpc/v0", fullNodeMethods, "Lotus Node", lotusPerms)
    run_methods(storageMinerOutput, "http://127.0.0.1:2345/rpc/v0", storageNodeMethods, "Storage Miner", lotusStoragePerms)
    run_methods(sealWorkerOutput, "http://127.0.0.1:3456/rpc/v0", workerNodeMethods, "Seal Worker", lotusStoragePerms)
    lotusOutput.close()
    storageMinerOutput.close()
    sealWorkerOutput.close()