--[[
	Fuji PTP over IP Protocol analyzer 
--[[
   References:
   [1] CIPA DC-X005-2005 - PTP-IP
   [3] gPhoto's Reversed Engineered PTP/IP documentation - http://gphoto.sourceforge.net/doc/ptpip.php
 --]]

----------------------------------------
-- do not modify this table
local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

----------------------------------------
-- set this DEBUG to debug_level.LEVEL_1 to enable printing debug_level info
-- set it to debug_level.LEVEL_2 to enable really verbose printing
-- set it to debug_level.DISABLED to disable debug printing
-- note: this will be overridden by user's preference settings
local DEBUG = debug_level.LEVEL_1

-- a table of our default settings - these can be changed by changing
-- the preferences through the GUI or command-line; the Lua-side of that
-- preference handling is at the end of this script file
local default_settings =
{
    debug_level  = DEBUG,
}


local dprint = function() end
local dprint2 = function() end
local function resetDebugLevel()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...)
            info(table.concat({"Lua: ", ...}," "))
        end

        if default_settings.debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    else
        dprint = function() end
        dprint2 = dprint
    end
end
-- call it now
resetDebugLevel()



local PTPIP_PACKETTYPE = {

    INVALID                = 0,
    INIT_COMMAND_REQUEST   = 1,
    INIT_COMMAND_ACK       = 2,
    INIT_EVENT_REQUEST     = 3,
    INIT_EVENT_ACK         = 4,
    INIT_FAIL              = 5,
    CMD_REQUEST            = 6,  -- possibly Operation request in [1] 2.3.6 agrees with [3]
    CMD_RESPONSE           = 7,  -- possibly Operation response in [1] 2.3 .7  agrees with [3]
    EVENT                  = 8,
    START_DATA_PACKET      = 9,
    DATA_PACKET            = 10,
    CANCEL_TRANSACTION     = 11,
    END_DATA_PACKET        = 12,
    PING                   = 13, -- possibly Probe Request in [1] 2.3.13 
    PONG                   = 14,  -- possibly Probe Response in [1] 2.3.14
} 

-- Unless otherwise stated, names are based on info in [3]
local PTPIP_PACKETTYPENAMES = {
    [PTPIP_PACKETTYPE.INVALID]=          "Invalid",
    [PTPIP_PACKETTYPE.INIT_COMMAND_REQUEST]=  "Init Command Request Packet",
    [PTPIP_PACKETTYPE.INIT_COMMAND_ACK]= "Init Command ACK Packet",
    [PTPIP_PACKETTYPE.INIT_EVENT_REQUEST]= "Init Event Request Packet",
    [PTPIP_PACKETTYPE.INIT_EVENT_ACK]=   "Init Event Ack Packet",
    [PTPIP_PACKETTYPE.INIT_FAIL]=        "Init Fail Packet",
    [PTPIP_PACKETTYPE.CMD_REQUEST]=      "Operation Request Packet",  -- string based on [1]
    [PTPIP_PACKETTYPE.CMD_RESPONSE]=     "Operation Response Packet", -- string based on [1]
    [PTPIP_PACKETTYPE.EVENT]=            "Event Packet",
    [PTPIP_PACKETTYPE.START_DATA_PACKET]="Start Data Packet",
    [PTPIP_PACKETTYPE.DATA_PACKET]=      "Data Packet",
    [PTPIP_PACKETTYPE.CANCEL_TRANSACTION]= "Cancel Packet",
    [PTPIP_PACKETTYPE.END_DATA_PACKET]=  "End Data Packet",
    [PTPIP_PACKETTYPE.PING]=             "Probe Request Packet",      -- string based on [1] 
    [PTPIP_PACKETTYPE.PONG]=             "Probe Response Packet",     -- string based on [1] 
    -- [PTPIP_PACKETTYPE.FUJI_DATA]=        "Fuji Data",     
}

-- keep here, it is referenced below

local hdr_fields =
{
	length = ProtoField.uint32("ptp.length","Length"),
    transaction_id = ProtoField.uint32("ptp.transactionID","TransactionID",base.HEX),
	header_tid_offset = ProtoField.uint32("ptp.headerTidOffset","TransactionID Offset",base.DEC),
	packet_type = ProtoField.uint32("ptp.pktType","PTP/IP Packet Type",base.HEX),
	fuji_packet_type = ProtoField.uint32("ptp.fujiPktType","Fuji Packet Type",base.HEX),
	opcode = ProtoField.uint16("ptp.fuji_opcode","Operation Code",base.HEX),
	unknown1 = ProtoField.uint16("ptp.fuji_unknown1","unknown1",base.HEX),
	-- the following packets relate to PTP/IP specific 
	guid = ProtoField.bytes( "ptpip.guid", "GUID" ),
    hostname =  ProtoField.string( "ptpip.name", "Host Name"),
    version = ProtoField.string( "ptpip.version", "Version", "ptpip.version" ),
    connection_number = ProtoField.uint32("ptpip.connection","Connection Number",base.HEX),
    dataphase_info = ProtoField.uint32("ptpip.dataphase", "Data Phase Info",base.HEX),
    packet_code = ProtoField.uint32("ptp.pktCode","code",base.HEX), -- one of opcode, reponsecode or eventcode
    data = ProtoField.bytes("ptp.data","data",base.HEX),
}

local data_hdr_fields =
{
	length = ProtoField.uint64("ptp.fujiDataStreamLength","Length"),
    stream_id = ProtoField.uint32("ptp.fujiStreamID","StreamID",base.HEX),
	unknown = ProtoField.uint32("ptp.fujiUnknownHeader","Unknown",base.HEX),
	-- data seems to be used otherwise:
    payload = ProtoField.bytes("ptp.payload","payload",base.HEX),
}

function dissect_none( tvb, proto, tree)  end 
local header_length = 6 -- UINT32 len + UINT16 fuji_type

--------------------------------------------------------------------------------
-- individual dissectors
--------------------------------------------------------------------------------

--[[
   Method to dissect the Init Command Request sent by the Initiator
   in the connection. This packet is defined by [1] Section 2.3.1
 --]]
 
function dissect_init_command_request_or_ack(tvb,pinfo,tree)
	local offset = header_length
	offset = offset + 2 -- The 'opcode' used in commad requests
	
	 -- there are additional four bytes compared to an PTP/IP request
	 -- it looks like fuji uses the same struct for request and ack:
    -- Grabbing the Connection Number 

    tree:add_le( hdr_fields.connection_number, tvb(offset,4) )
    offset = offset + 4
    
    offset = offset + dissect_guid(tvb, pinfo, tree, offset)
    
    -- grabbing the name
    offset = offset + dissect_unicode_name(tvb, pinfo, tree, offset)

    --[[ grabbing protocol version
         Note: [3] does not list this in the packet field. . [1] 2.3.1 states it's the last 4
         bytes of the packet.
    --]]
    offset = offset + dissect_protocol_version(tvb, pinfo, tree, offset)
end

--[[
   Dissects the Init Event Request packet specified in [1] Section 2.3.3.
   Standard states that the packet only has 1 field.
 --]]
 
function dissect_init_event_request(tvb, pinfo, tree)
    -- Grabbing the Connection Number 
    tree:add_le( hdr_fields.connection_number, tvb(8,4) )
end

--[[
   Dissects the Init Event Ack packet specified in [1] Section 2.3.4
 --]]
 
function dissect_init_event_ack(tvb, pinfo, tree)
    -- packet has no payload. 
end

--[[
 * Dissects the Event Packet specified in [1] Section 2.3.8
 * Note: many of the fields in this packet move from PTP/IP to PTP layer
 * of the stack.  Work will need to be done in future iterations to make this
 * compatible with PTP/USB.
 --]]
function dissect_event(tvb, pinfo, tree)
    local offset = header_length 
    tree:add_le(hdr_fields.packet_code,  tvb(offset, 2))
    add_ptp_transactionID(tvb, pinfo, tree, offset + 2)
end

--[[
 * Dissects the Event Packet specified in [1] Section 2.3.9
 * Note: many of the fields in this packet move from PTP/IP to PTP layer
 * of the stack.  Work will need to be done in future iterations to make this
 * compatible with PTP/USB.
 --]]
function dissect_start_data(tvb, pinfo, tree)
    local offset = header_length
    tree:add_le(hdr_fields.packet_code, tvb(offset,2))
    offset = offset + add_ptp_transactionID(tvb, pinfo, tree, offset + 2)
    --local length_lowword = tvb(offset, 4):le_uint()
    --local length_hiword = tvb(offset + 4, 4):le_uint()
    --local length = UInt64( length_lowword, length_hiword )
    
    --tree:add(hdr_fields.data_length, tvb(offset, 8), length )
    
     -- [1] specifies in 2.3.9 if total data len is this value then len is unknown 
     -- if (dataLen == G_GUINT64_CONSTANT(0xFFFFFFFFFFFFFFFF))    
     --   col_append_str(  pinfo->cinfo, COL_INFO, " Data Length Unknown");
end

function dissect_data(tvb, pinfo, tree)
	local offset = header_length 
    add_ptp_transactionID(tvb, pinfo, tree, offset)
end

--[[
 * Dissects the End Data specified in [1] Section 2.3.11
 * Note: many of the fields in this packet move from PTP/IP to PTP layer
 * of the stack.  Work will need to be done in future iterations to make this
 * compatible with PTP/USB.
 --]]
function dissect_end_data(tvb, pinfo, tree)
	local offset = header_length
    add_ptp_transactionID(tvb, pinfo, tree, offset)
end

--[[
 * Dissects the Operation Request Packet specified in [1] Section 2.3.6
 * Note: many of the fields in this packet move from PTP/IP to PTP layer
 * of the stack.  Work will need to be done in future iterations to make this
 * compatible with PTP/USB.
 
 
 --]]
 
function dissect_operation_request(tvb, pinfo, tree)
    local offset = header_length
    tree:add_le(hdr_fields.packet_code, tvb(offset,2)) -- 4 bytes
    add_ptp_transactionID(tvb, pinfo, tree, offset + 2)
    -- tree:add('data',tvb(8))
end 

--[[
 * Dissects the Operation Response Packet specified in [1] Section 2.3.7
 * Note: many of the fields in this packet move from PTP/IP to PTP layer
 * of the stack.  Work will need to be done in future iterations to make this
 * compatible with PTP/USB.
 --]]
function dissect_operation_response(tvb, pinfo, tree)
	local offset = header_length
    tree:add_le(hdr_fields.packet_code, tvb(offset, 2))
    add_ptp_transactionID(tvb, pinfo, tree, offset + 2)
end

--[[
 * The transaction ID is defined  in [2]  9.3.1
 * and used in multiple message types. This method handles
 * parsing the field and adding the value to the info
 * column.
 *
 --]]
function add_ptp_transactionID(tvb, pinfo, tree, offset)
 	tree:add(hdr_fields.header_tid_offset, offset)
	tree:add_le(hdr_fields.transaction_id, tvb(offset,4))
	return 4
end

function dissect_fuji_data(tvb, pinfo, tree)
    offset = header_length
    tree:add_le(hdr_fields.opcode, tvb(offset,2))
    offset = offset + 2
    offset = offset + add_ptp_transactionID(tvb, pinfo, tree, offset)
	
	tree:add(hdr_fields.data, tvb(offset))
end

local FUJI_TO_PTPIP_PACKETTYPE = {
	[1] = PTPIP_PACKETTYPE.CMD_REQUEST,
	[2] = PTPIP_PACKETTYPE.START_DATA_PACKET,
	[3] = PTPIP_PACKETTYPE.CMD_RESPONSE,
	[4] = PTPIP_PACKETTYPE.EVENT,
	[0xFFFF] = PTPIP_PACKETTYPE.CANCEL_TRANSACTION -- unknown, seems to be some error (seen after some syn errors)
}
 
local PTPIP_DISSECTORS = {
    [PTPIP_PACKETTYPE.INVALID]=          dissect_none,
    [PTPIP_PACKETTYPE.INIT_COMMAND_REQUEST]=  dissect_init_command_request_or_ack,
    [PTPIP_PACKETTYPE.INIT_COMMAND_ACK]= dissect_init_command_request_or_ack,
    [PTPIP_PACKETTYPE.INIT_EVENT_REQUEST]= dissect_init_event_request,
    [PTPIP_PACKETTYPE.INIT_EVENT_ACK]=  dissect_init_event_ack,
    [PTPIP_PACKETTYPE.INIT_FAIL]=        dissect_none,
    [PTPIP_PACKETTYPE.CMD_REQUEST]=      dissect_operation_request,
    [PTPIP_PACKETTYPE.CMD_RESPONSE]=     dissect_operation_response,
    [PTPIP_PACKETTYPE.EVENT]=            dissect_event,
    [PTPIP_PACKETTYPE.START_DATA_PACKET]=dissect_start_data,
    [PTPIP_PACKETTYPE.DATA_PACKET]=     dissect_data,
    [PTPIP_PACKETTYPE.CANCEL_TRANSACTION]= dissect_none,
    [PTPIP_PACKETTYPE.END_DATA_PACKET]=  dissect_fuji_data,
    [PTPIP_PACKETTYPE.PING]=             dissect_none, 
    [PTPIP_PACKETTYPE.PONG]=             dissect_none, 
    -- [PTPIP_PACKETTYPE.FUJI_DATA]=        dissect_fuji_data, 
}

-- PTP/IP protocol 
ptpip_proto = Proto("PTPIP-FUJI","FUJI PTP/IP Protocol to PTP")
ptpip_proto.fields = hdr_fields

datastream_proto = Proto("PTPIP-STREAM-FUJI","FUJI PTP/IP Datastream")
datastream_proto.fields = data_hdr_fields

-- create a function to dissect it
function ptpip_proto.dissector(tvb,pinfo,tree)
	local ptp_dissector_table = DissectorTable.get("ptp.data")
	packet_dissector = ptp_dissector_table:get_dissector('ptp') 
	if not  packet_dissector then
		dprint('Can not find ptp dissector' )
	end

   pinfo.cols.protocol = "FUJI PTP/IP"
   
   local ptp_length_tvb = tvb(0,4)
   local ptp_length =  ptp_length_tvb:le_uint()
   
   local packet_type_tvb = tvb(4,2)
   local packet_type = packet_type_tvb:le_uint()    
   -- local ptpip_packet_type = packet_type
   
   local ptpip_packet_type = PTPIP_PACKETTYPE.DATA_PACKET
   local opcode = tvb( header_length ,2):le_uint()
   if opcode and FUJI_TO_PTPIP_PACKETTYPE[packet_type] then 
       	   ptpip_packet_type = FUJI_TO_PTPIP_PACKETTYPE[packet_type]  
   end
         
   local prefix = "FUJI PTP/IP: "
   if opcode ~= 0 then 
   		prefix = 'PTP: '
   else 
   		ptpip_packet_type = PTPIP_PACKETTYPE.INIT_COMMAND_REQUEST
   end
   
   local packet_type_name = PTPIP_PACKETTYPENAMES[ptpip_packet_type] or 'Unknown'   
   local subtree = tree:add(ptpip_proto,tvb(), prefix .. packet_type_name )
   if ptpip_packet_type then subtree:add(hdr_fields.packet_type, ptpip_packet_type) end -- 16 bit in USB

   if ptpip_packet_type == PTPIP_PACKETTYPE.DATA_PACKET then 
      return 
   end
   subtree:add_le(hdr_fields.length, ptp_length_tvb)
   -- subtree:add_le(hdr_fields.data_direction, tvb(8,4)) 
   subtree:add_le(hdr_fields.fuji_packet_type, packet_type_tvb)

   local buffer_length = tvb:reported_length_remaining()
   buffer_length = math.min( buffer_length, ptp_length )
    
   local dissect_remainder = PTPIP_DISSECTORS[ptpip_packet_type]
   if dissect_remainder then 
       dissect_remainder(tvb,pinfo,subtree)
   else
       dprint('No dissector for packet type ' .. packet_type)
   end

   if packet_dissector then
   		packet_dissector(tvb,pinfo,tree)
   end

end
  
function  datastream_proto.dissector(tvb,pinfo,tree)
--  now here we enter total observation land: 
	pinfo.cols.protocol = "FUJI PTP DATA STREAM"
	if tvb:reported_length_remaining() > 16 then 
		local length_tvb = tvb(0, 8)
	
		local sid_tvb = tvb(8,4)
		local unknown_tvb = tvb(12,4)
		local unknown_value = unknown_tvb:le_uint()

		if unknown_value == 0 then 
			local tree = tree:add(datastream_proto,tvb(), 'Fuji start data (' .. length_tvb:le_uint64() .. ' bytes)' )
			tree:add(data_hdr_fields.length, length_tvb, length_tvb:le_uint64() )
			tree:add(data_hdr_fields.stream_id, sid_tvb, sid_tvb:le_uint() )
			tree:add(data_hdr_fields.unknown, unknown_tvb, unknown_tvb:le_uint() )
			tree:add(data_hdr_fields.payload,tvb(16))
		else
		    local tree = tree:add(datastream_proto,tvb(), 'Fuji datastream without header - continued data?')
		    tree:add(data_hdr_fields.payload,tvb())
		end
	end

end

-- load the tcp.port table
tcp_table = DissectorTable.get("tcp.port")
-- register our protocol 
tcp_table:add(55740,ptpip_proto)
tcp_table:add(55741,ptpip_proto)
tcp_table:add(55742,datastream_proto)

--[[
 * This method handles dissecting the Unicode name that is
 * specificed in multiple packets.
 --]]
function dissect_unicode_name(tvb, pinfo, tree, offset)
	name = tvb(offset):le_ustringz()
	tree:add( hdr_fields.hostname, name )
	
	-- how do i get the bytes consumed? 
	dprint2( 'name length ' ..  name:len() )
	return (name:len() + 1) * 2 
end

--[[ Method dissects the protocol version from the packets.
 * Additional note, section 3 of [1] defines the Binary Protocol version
 * as 0x00010000 == 1.0 where the Most significant bits are the major version and the least
 * significant bits are the minor version.
 --]]
function dissect_protocol_version(tvb, pinfo, tree, offset)

	local buffer_length = tvb:reported_length_remaining()
	if buffer_length >= offset + 4 then
		minor_version = tvb(offset,2):le_uint()
		offset = offset + 2
		major_version = tvb(offset,2):le_uint()
		version_string = major_version .. '.' .. minor_version
		tree:add( hdr_fields.version, version_string )
		-- return bytes consumed 
    	return 4
	else
		debug( 'Can not read 4 bytes from ' .. offset .. ': total: ' .. buffer_length )
	end
	return 0

end

-- Grabbing the GUID 
function dissect_guid( tvb, pinfo, tree, offset)
	local PTPIP_GUID_SIZE = 16
	
	guid = tvb(offset, PTPIP_GUID_SIZE)
	tree:add(hdr_fields.guid, guid)

 -- return bytes consumed 
 	return PTPIP_GUID_SIZE
end



--------------------------------------------------------------------------------
-- preferences handling stuff
--------------------------------------------------------------------------------

local debug_pref_enum = {
    { 1,  "Disabled", debug_level.DISABLED },
    { 2,  "Level 1",  debug_level.LEVEL_1  },
    { 3,  "Level 2",  debug_level.LEVEL_2  },
}

----------------------------------------
-- register our preferences

ptpip_proto.prefs.debug       = Pref.enum("Debug", default_settings.debug_level,
                                        "The debug printing level", debug_pref_enum)

----------------------------------------
-- the function for handling preferences being changed
function ptpip_proto.prefs_changed()
    dprint2("prefs_changed called")

    default_settings.debug_level = ptpip_proto.prefs.debug
    resetDebugLevel()

end

--[[
dissector_tables = DissectorTable.list()
for dissector_name in dissector_tables do
	dprint2( dissector_name )
end
dprint2("pcapfile Prefs registered")
--]]

