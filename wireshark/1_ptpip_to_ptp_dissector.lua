--[[
	PTPIP Protocol analyzer based on the original wireshark analyzer
--]]


--[[
    References:
   [1] CIPA DC-X005-2005 - PTP-IP
   [2] BS ISO 15740:2008 - Photography Electronic still picture imaging - Picture transfer protocol (PTP)
   for digital still photography devices
   [3] gPhoto's Reversed Engineered PTP/IP documentation - http://gphoto.sourceforge.net/doc/ptpip.php
   [4] gPhoto's ptp2 header file  https://gphoto.svn.sourceforge.net/svnroot/gphoto/trunk/libgphoto2/camlibs/ptp2/ptp.h
 --]]

--[[ PTP Definitions *
   String Names of packet types [3] & [4]
   Opcode 0x1000 - 0x1025 defined in Table 22 of [2]
   Remainder of Opcodes from [4]. Enums reformatted from [4] ptp.h
--]]

--[[
	String Names of packet types [3] & [4]
	PTP/IP definitions 
	enums reformatted from [4]
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
    PONG                   = 14  -- possibly Probe Response in [1] 2.3.14
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
}

-- keep here, it is referenced below

local hdr_fields =
{
	length = ProtoField.uint32("ptp.length","Length"),
	header_tid_offset = ProtoField.uint32("ptp.headerTidOffset","TransactionID Offset",base.DEC),
	packet_type = ProtoField.uint32("ptp.pktType","Packet Type",base.HEX),
	-- opcode = ProtoField.uint16("ptp.opcode","Operation Code",base.HEX),
	-- transaction_id = ProtoField.uint32("ptp.transactionID","Transaction ID",base.HEX)
	-- the following packets relate to PTP/IP specific 
	guid = ProtoField.bytes( "ptpip.guid", "GUID" ),
    hostname =  ProtoField.string( "ptpip.name", "Host Name"),
    version = ProtoField.string( "ptpip.version", "Version", "ptpip.version" ),
    connection_number = ProtoField.uint32("ptpip.connection","Connection Number",base.HEX),
    dataphase_info = ProtoField.uint32("ptpip.dataphase", "Data Phase Info",base.HEX),
    transaction_id = ProtoField.uint32("ptp.transactionID","Transaction ID",base.HEX),
    data_length = ProtoField.uint64("ptp.dataLen","dataLen",base.HEX),
    packet_code = ProtoField.uint32("ptp.pktCode","code",base.HEX), -- one of opcode, reponsecode or eventcode
}


local header_length = 8 -- UINT32 len + UINT32 type

function dissect_none( tvb, proto, tree)  end 

--------------------------------------------------------------------------------
-- individual dissectors
--------------------------------------------------------------------------------

--[[
   Method to dissect the Init Command Request sent by the Initiator
   in the connection. This packet is defined by [1] Section 2.3.1
 --]]
 
function dissect_init_command_request(tvb,pinfo,tree)
	local offset = header_length
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
   Method to dissect the Init Command Ack sent by the Responder
   in the connection. This packet is defined by [1] Section 2.3.2
--]]

function dissect_init_command_ack(tvb,pinfo,tree)
    local offset = header_length

    -- Grabbing the Connection Number 
    tree:add_le( hdr_fields.connection_number, tvb(offset,4) )
    offset = offset + 4

    offset = offset + dissect_guid(tvb, pinfo, tree, offset);

    -- grabbing name
    offset = offset + dissect_unicode_name(tvb,pinfo, tree, offset);

    --[[ grabbing protocol version. Note: like in the Init Command Request, [3] doesn't mention
      this field, but [1] Section 2.3.2 does.
     --]]

    offset = offset + dissect_protocol_version(tvb, pinfo, tree, offset);
end


--[[
   Dissects the Init Event Request packet specified in [1] Section 2.3.3.
   Standard states that the packet only has 1 field.
 --]]
 
function dissect_init_event_request(tvb, pinfo, tree)
    -- Grabbing the Connection Number 
     local offset = header_length
    tree:add_le( hdr_fields.connection_number, tvb(offset,4) )
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
    offset = offset + add_ptp_transactionID(tvb, pinfo, tree, offset)
    local length_lowword = tvb(offset, 4):le_uint()
    local length_hiword = tvb(offset + 4, 4):le_uint()
    local length = UInt64( length_lowword, length_hiword )
    
    tree:add(hdr_fields.data_length, tvb(offset, 8), length )
    
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
    tree:add_le(hdr_fields.dataphase_info, tvb(offset,4)) -- 4 bytes
    tree:add_le(hdr_fields.packet_code,  tvb(offset + 4, 2))
    add_ptp_transactionID(tvb, pinfo, tree, offset + 6)
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

 
local PTPIP_DISSECTORS = {
    [PTPIP_PACKETTYPE.INVALID]=          dissect_none,
    [PTPIP_PACKETTYPE.INIT_COMMAND_REQUEST]=  dissect_init_command_request,
    [PTPIP_PACKETTYPE.INIT_COMMAND_ACK]= dissect_init_command_ack,
    [PTPIP_PACKETTYPE.INIT_EVENT_REQUEST]= dissect_init_event_request,
    [PTPIP_PACKETTYPE.INIT_EVENT_ACK]=  dissect_init_event_ack,
    [PTPIP_PACKETTYPE.INIT_FAIL]=        dissect_none,
    [PTPIP_PACKETTYPE.CMD_REQUEST]=      dissect_operation_request,
    [PTPIP_PACKETTYPE.CMD_RESPONSE]=     dissect_operation_response,
    [PTPIP_PACKETTYPE.EVENT]=            dissect_event,
    [PTPIP_PACKETTYPE.START_DATA_PACKET]=dissect_start_data,
    [PTPIP_PACKETTYPE.DATA_PACKET]=     dissect_data,
    [PTPIP_PACKETTYPE.CANCEL_TRANSACTION]= dissect_none,
    [PTPIP_PACKETTYPE.END_DATA_PACKET]=  dissect_end_data,
    [PTPIP_PACKETTYPE.PING]=             dissect_none, 
    [PTPIP_PACKETTYPE.PONG]=             dissect_none, 
}

-- PTP/IP protocol 
ptpip_proto = Proto("PTPIP-Lua","PTP/IP Protocol to PTP")
ptpip_proto.fields = hdr_fields

-- create a function to dissect it
function ptpip_proto.dissector(tvb,pinfo,tree)
	local ptp_dissector_table = DissectorTable.get("ptp.data")
	local packet_dissector = ptp_dissector_table:get_dissector('ptp') 
	if not  packet_dissector then
		dprint('Can not find ptp dissector' )
	end

   pinfo.cols.protocol = "PTP/IP"
   
   local ptp_length =  tvb(0,4):le_uint()
   local packet_type = tvb(4,4):le_uint()
   
   local prefix = "PTP/IP: "
   if packet_type == PTPIP_PACKETTYPE.CMD_REQUEST 
   		or packet_type == PTPIP_PACKETTYPE.CMD_RESPONSE 
   		or packet_type == PTPIP_PACKETTYPE.EVENT then
   		prefix = 'PTP: '
   end
   
   local subtree = tree:add(ptpip_proto,tvb(), prefix .. PTPIP_PACKETTYPENAMES[packet_type] )
   subtree:add_le(hdr_fields.length, tvb(0,4))
   subtree:add_le(hdr_fields.packet_type, tvb(4,4)) -- 16 bit in USB
   -- subtree:add_le(hdr_fields.data_direction, tvb(8,4)) 
   
   -- local header_tid_offset = 8
   -- if packet_type == PTPIP_PACKETTYPE.CMD_REQUEST then header_offset = 12 end
   -- if packet_type == PTPIP_PACKETTYPE.CMD_RESPONSE or packet_type == PTPIP_PACKETTYPE.EVENT then header_offset = 12 end
   
   
   local buffer_length = tvb:reported_length_remaining()
   buffer_length = math.min( buffer_length, ptp_length )
    
   local dissect_remainder = PTPIP_DISSECTORS[packet_type]
   if dissect_remainder then 
       dissect_remainder(tvb,pinfo,subtree)
   else
       dprint('No dissector for packet type ' .. packet_type)
   end

   if packet_dissector then
   		packet_dissector(tvb,pinfo,tree)
   end
end
  
-- load the tcp.port table
tcp_table = DissectorTable.get("tcp.port")
-- register our protocol 
tcp_table:add(15740,ptpip_proto)

--[[
 * This method handles dissecting the Unicode name that is
 * specificed in multiple packets.
 --]]
function dissect_unicode_name(tvb, pinfo, tree, offset)
	local name = tvb(offset):le_ustringz()
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

end

-- Grabbing the GUID 
function dissect_guid( tvb, pinfo, tree, offset)
	local PTPIP_GUID_SIZE = 16
	local guid = tvb(offset, PTPIP_GUID_SIZE)
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

