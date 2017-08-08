# test bitmap

mdb = MetaDB("c:\\temp\\inVtero.net")

mdb.HDB.GetIdxBit(0x10)
mdb.HDB.GetIdxBit(0x20)
mdb.HDB.GetIdxBit(0x100)
mdb.HDB.GetIdxBit(0x1000)
mdb.HDB.GetIdxBit(0x10000)
mdb.HDB.GetIdxBit(0x1000000)

mdb.HDB.GetIdxBit(0x1fffff00000fff0)
mdb.HDB.SetIdxBit(0x1fffff00000fff0)
mdb.HDB.GetIdxBit(0x1fffff00000fff0)

from inVtero.net.Support import WebAPI
WebAPI.GET("14,234,0x415b1ddfc51fe23,415b1ddfc51fe23")


