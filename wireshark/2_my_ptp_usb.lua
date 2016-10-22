local PTP_PACKETTYPE = {
	UNDEF = 0,
	CMD   = 1,
	DATA  = 2,
	ACK   = 3,
	EVENT = 4
}
local PTP_PACKETTYPENAMES = {
	[PTP_PACKETTYPE.UNDEF]="Undef",
	[PTP_PACKETTYPE.CMD]  ="Command",
	[PTP_PACKETTYPE.DATA] ="Data",
	[PTP_PACKETTYPE.ACK]  ="Ack",
	[PTP_PACKETTYPE.EVENT]="Event"
}

ptpusb_proto = Proto("ptpusb","PTP/USB")
local ptpusb = {
	plen   = ProtoField.uint32("ptpusb.plen",  "Length"),
	ptype  = ProtoField.uint16("ptpusb.ptype", "Type"),
	code   = ProtoField.uint16("ptpusb.code",  "Code", base.HEX),
	tid    = ProtoField.uint32("ptpusb.tid",   "TransactionID", base.HEX),
	param  = ProtoField.uint32("ptpusb.param", "Param", base.HEX),
	resp   = ProtoField.uint32("ptpusb.resp",  "Response", base.HEX),
}
ptpusb_proto.fields = {ptpusb.plen, ptpusb.ptype, ptpusb.code, ptpusb.tid, ptpusb.param, ptpusb.resp}

--usb_idvendor = Field.new("usb.idVendor")
usb_capdata  = Field.new("usb.capdata")
usb_iclass   = Field.new("usb.bInterfaceClass")

function ptpusb_proto.dissector(tvb,pinfo,tree)
	--local idvendor = usb_idvendor()
	local capdata = usb_capdata()
	local iclass  = usb_iclass()
	if capdata and iclass and iclass.value == 6 then -- Imaging
		local size = capdata.len
		local start = tvb:len() - size
		local plen_tvb  = tvb(start,4)
		local ptype_tvb = tvb(start+4,2)
		local code_tvb  = tvb(start+6,2)
		local tid_tvb   = tvb(start+8,4)
		local plen  = plen_tvb:le_uint()
		local ptype = ptype_tvb:le_uint()
		if size > 512 or (size == 512 and ptype ~= 2) then -- @bug this is buggy. bulk data are after a packet "plen > size" until ACK.
			tree:add(ptpusb_proto, tvb(start, size), "PTP/USB: Bulk Data")
			return
		end
		local subtree = tree:add(ptpusb_proto, tvb(start, size), "PTP/USB: " .. PTP_PACKETTYPENAMES[ptype])
		subtree:add_le(ptpusb.plen,  plen_tvb)
		subtree:add_le(ptpusb.ptype, ptype_tvb)
		subtree:add_le(ptpusb.code,  code_tvb)
		subtree:add_le(ptpusb.tid,   tid_tvb)
		local offset = start + 12
		local stop   = start + size
		if offset < stop then
			if ptype == PTP_PACKETTYPE.CMD then
				while (offset < stop) do
					subtree:add_le(ptpusb.param, tvb(offset,4))
					offset = offset+4
				end
			elseif ptype == PTP_PACKETTYPE.DATA then
				----@TODO parse after field
			elseif ptype == PTP_PACKETTYPE.ACK then
				subtree:add_le(ptpusb.resp, tvb(offset,4))
			elseif ptype == PTP_PACKETTYPE.EVENT then
				subtree:add_le(ptpusb.param, tvb(offset,4))
			end
		end
	end
end

register_postdissector(ptpusb_proto)