import Foundation
let cases: [(String?, Int?, SignalActivityMode)] = [
 ("LTE",1,.lte),("LTE",2,.lteCA),("LTE-NSA",2,.nsa),("NR5G-SA",2,.sa),
 ("5G_SA",nil,.sa),("4G+",nil,.lteCA),("EN-DC",nil,.nsa),
 ("NO_SERVICE",2,.noService),("LIMITED_SERVICE",2,.noService),(nil,2,.unknown),
 ("5G",nil,.unknown),("WCDMA",nil,.unknown)
]
for (raw,count,wanted) in cases { precondition(SignalActivityMode(networkType:raw,lteCarrierCount:count)==wanted) }
precondition(!SignalActivityMode.sa.showsLTE)
precondition(!SignalActivityMode.lteCA.showsNR)
precondition(SignalActivityMode.nsa.showsLTE && SignalActivityMode.nsa.showsNR)
precondition(!SignalActivityMode.noService.showsLTE && !SignalActivityMode.noService.showsNR)
print("12 mode classifications and radio visibility checks passed")
