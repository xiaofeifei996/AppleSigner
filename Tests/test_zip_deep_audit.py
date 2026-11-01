#!/usr/bin/env python3
"""Independent ZIP local-record/descriptor reference tests; not Objective-C execution tests."""
import struct, zlib, binascii, unittest

LOCAL=b"PK\x03\x04"
CENTRAL=b"PK\x01\x02"
EOCD=b"PK\x05\x06"
DD=b"PK\x07\x08"

def raw_deflate(data):
    c=zlib.compressobj(wbits=-15)
    return c.compress(data)+c.flush()

def make_zip(entries, descriptor=False):
    local=bytearray()
    central=bytearray()
    for name, plain, method in entries:
        name=name.encode()
        compressed=plain if method==0 else raw_deflate(plain)
        crc=binascii.crc32(plain)&0xffffffff
        flags=0x0008 if descriptor else 0
        offset=len(local)
        local += struct.pack("<IHHHHHIIIHH",0x04034b50,20,flags,method,0,0,
                             0 if descriptor else crc,
                             0 if descriptor else len(compressed),
                             0 if descriptor else len(plain),len(name),0)+name+compressed
        if descriptor:
            local += DD+struct.pack("<III",crc,len(compressed),len(plain))
        central += struct.pack("<IHHHHHHIIIHHHHHII",0x02014b50,0x0314,20,flags,
                               method,0,0,crc,len(compressed),len(plain),
                               len(name),0,0,0,0,0,offset)+name
    cd_off=len(local)
    count=len(entries)
    return bytes(local+central+struct.pack("<IHHHHIIH",0x06054b50,0,0,count,count,
                                           len(central),cd_off,0))

def audit(data):
    e=data.rfind(EOCD)
    if e<0: raise ValueError("eocd")
    _,disk,cd_disk,n_disk,n_total,cd_size,cd_off,comment=struct.unpack_from("<IHHHHIIH",data,e)
    if disk or cd_disk or n_disk!=n_total or cd_off+cd_size>e: raise ValueError("central bounds")
    cur=cd_off
    ranges=[]
    for _ in range(n_total):
        if data[cur:cur+4]!=CENTRAL: raise ValueError("central")
        flags,method=struct.unpack_from("<HH",data,cur+8)
        crc,cs,us=struct.unpack_from("<III",data,cur+16)
        nl,el,cl=struct.unpack_from("<HHH",data,cur+28)
        off=struct.unpack_from("<I",data,cur+42)[0]
        name=data[cur+46:cur+46+nl]
        if cur+46+nl+el+cl>cd_off+cd_size: raise ValueError("central extent")
        if data[off:off+4]!=LOCAL: raise ValueError("local signature")
        lf,lm=struct.unpack_from("<HH",data,off+6)
        lcrc,lcs,lus=struct.unpack_from("<III",data,off+14)
        lnl,lel=struct.unpack_from("<HH",data,off+26)
        if lf!=flags or lm!=method or lnl!=nl: raise ValueError("local mismatch")
        data_pos=off+30+lnl+lel
        if data[off+30:off+30+lnl]!=name: raise ValueError("local name")
        if data_pos+cs>cd_off: raise ValueError("data bounds")
        descriptor=bool(flags&8)
        if descriptor:
            if (lcrc not in (0,crc) or lcs not in (0,cs) or lus not in (0,us)):
                raise ValueError("descriptor local values")
        elif (lcrc,lcs,lus)!=(crc,cs,us):
            raise ValueError("local crc/size")
        payload=data[data_pos:data_pos+cs]
        if method==0:
            if cs!=us: raise ValueError("stored length")
            plain=payload
        elif method==8:
            dec=zlib.decompressobj(-15)
            plain=dec.decompress(payload)+dec.flush()
            if not dec.eof or dec.unused_data or dec.unconsumed_tail:
                raise ValueError("deflate trailing/truncated")
        else: raise ValueError("method")
        if len(plain)!=us or (binascii.crc32(plain)&0xffffffff)!=crc:
            raise ValueError("content integrity")
        end=data_pos+cs
        if descriptor:
            if data[end:end+4]==DD:
                got=struct.unpack_from("<III",data,end+4); end+=16
            else:
                got=struct.unpack_from("<III",data,end); end+=12
            if got!=(crc,cs,us): raise ValueError("descriptor values")
        if end>cd_off: raise ValueError("record bounds")
        ranges.append((off,end))
        cur+=46+nl+el+cl
    if cur!=cd_off+cd_size: raise ValueError("central size")
    ranges.sort()
    for a,b in zip(ranges,ranges[1:]):
        if b[0]<a[1]: raise ValueError("overlap")
    return True

class DeepZIPTests(unittest.TestCase):
    def test_stored_valid(self):
        self.assertTrue(audit(make_zip([("Payload/a",b"abc",0)])))
    def test_deflate_valid(self):
        self.assertTrue(audit(make_zip([("Payload/a",b"abc"*100,8)])))
    def test_signed_descriptor_valid(self):
        self.assertTrue(audit(make_zip([("Payload/a",b"descriptor",8)],True)))
    def test_unsigned_descriptor_valid(self):
        z=bytearray(make_zip([("Payload/a",b"descriptor",8)],True))
        # Remove descriptor signature; adjust central directory and EOCD offsets.
        e=z.rfind(EOCD); _,_,_,_,count,cdsize,cdoff,_=struct.unpack_from("<IHHHHIIH",z,e)
        central=bytes(z[cdoff:cdoff+cdsize])
        local=bytearray(z[:cdoff])
        # Signature is immediately before descriptor CRC after compressed payload.
        # Locate signature from the descriptor payload by searching after local header.
        pos=local.find(DD)
        del local[pos:pos+4]
        newoff=cdoff-4
        z=local+central+struct.pack("<IHHHHIIH",0x06054b50,0,0,count,count,cdsize,newoff,0)
        self.assertTrue(audit(bytes(z)))
    def test_descriptor_crc_mismatch_rejected(self):
        z=bytearray(make_zip([("Payload/a",b"descriptor",8)],True))
        e=z.rfind(EOCD); cdoff=struct.unpack_from("<I",z,e+16)[0]
        pos=z.find(DD)+4
        z[pos]^=0x01
        with self.assertRaises(ValueError): audit(bytes(z))
    def test_local_header_crc_mismatch_rejected(self):
        z=bytearray(make_zip([("Payload/a",b"abc",0)]))
        z[14]^=1
        with self.assertRaises(ValueError): audit(bytes(z))
    def test_deflate_trailing_bytes_rejected(self):
        z=bytearray(make_zip([("Payload/a",b"abc",8)]))
        # Insert an extra byte at the end of compressed data and update central size.
        e=z.rfind(EOCD); cdoff=struct.unpack_from("<I",z,e+16)[0]
        # single central record
        cs=struct.unpack_from("<I",z,cdoff+20)[0]
        z[cdoff:cdoff]=b"X"
        cdoff+=1; e+=1
        struct.pack_into("<I",z,cdoff+20,cs+1)
        struct.pack_into("<I",z,18,cs+1)  # local header compressed-size field
        struct.pack_into("<I",z,e+16,cdoff)
        struct.pack_into("<I",z,e+12,struct.unpack_from("<I",z,e+12)[0])
        with self.assertRaises(ValueError): audit(bytes(z))
    def test_overlapping_local_records_rejected(self):
        z=bytearray(make_zip([("Payload/a",b"a",0),("Payload/a",b"a",0)]))
        e=z.rfind(EOCD); cdoff=struct.unpack_from("<I",z,e+16)[0]
        second=cdoff+46+len("Payload/a")
        struct.pack_into("<I",z,second+42,0)
        with self.assertRaises(ValueError): audit(bytes(z))

if __name__=="__main__":
    unittest.main(verbosity=2)
