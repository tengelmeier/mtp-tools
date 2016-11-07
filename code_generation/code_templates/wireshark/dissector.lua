{% import 'macros.template' as macros %}
--[[
	PTP Protocol analyzer based on the original wireshark analyzer
	Adjusted by T. Engelmeier
]]

--[[
    References:
   [1] CIPA DC-X005-2005 - PTP-IP
   [2] BS ISO 15740:2008 - Photography Electronic still picture imaging - Picture transfer protocol (PTP)
   for digital still photography devices
   [3] gPhoto's Reversed Engineered PTP/IP documentation - http://gphoto.sourceforge.net/doc/ptpip.php
   [4] gPhoto's ptp2 header file  https://gphoto.svn.sourceforge.net/svnroot/gphoto/trunk/libgphoto2/camlibs/ptp2/ptp.h

   [5] ISO+15740-2008.pdf PTP 1.1 standard
   [6] etl_WPDMTP.events.npl

	To be able to handle various formats of PTP the main dissector has to pass a number of parsed data
	- session_id
	- transaction_id
	- code [opcode, responsecode or eventcode]
	- header_tid_offset [offset of transaction_id].
	-- While it would be more logical to pass e.g. the first byte after tid, here the tid is mapped


	this allows to handle packets which are structured (op = request, resp = response or event)


	op in PTP [5]     op in PTP/IP [1]    resp in PTP        resp in PTP/IP
	                  UINT32 len                              UINT32 len
	                  UINT32 packet_type                      UINT32 packet_type
	                  UINT32 dataphase
    UINT16 opcode     UINT16 opcode        UINT16 code        UINT16 code
    UINT32 sessionid                       UINT32 sessionid
    UINT32 tid        UINT32 tid           UINT32 tid         UINT32 tid

    Additionally, we handle PTP/IP start data and data packets.
    They are formally PTP/IP only but otherwise there is no notion of the data stream in PTP

--]]

--[[
	String Names of packet types [3] & [4]
	PTP/IP definitions - interface to the 'Parent' PTP dissector
--]]

PTPIP_PACKETTYPE = {
    INVALID                = 0,
    INIT_COMMAND_REQUEST   = 1,
    INIT_COMMAND_ACK       = 2,
    INIT_EVENT_REQUEST     = 3,
    INIT_EVENT_ACK         = 4,
    INIT_FAIL              = 5,
    CMD_REQUEST            = 6,  -- possibly Operation request in [1] 2.3.6 agrees with [3]
    CMD_RESPONSE           = 7,  -- possibly Operation response in [1] 2.3.7  agrees with [3]
    EVENT                  = 8,
    START_DATA_PACKET      = 9,
    DATA_PACKET            = 10,
    CANCEL_TRANSACTION     = 11,
    END_DATA_PACKET        = 12,
    PING                   = 13, -- possibly Probe Request in [1] 2.3.13
    PONG                   = 14  -- possibly Probe Response in [1] 2.3.14
}
-----------------------------------------------
-- main MTP definitions - extracted from [6]

-- Requests
    {{ macros.generate_opcodes('MTP_OPERATION', tables['OpCode']) }}

-- Request parameter descriptions
    {{ macros.generate_parameters('MTP_REQUEST_PARAMETERS', tables['Commands']) }}

-- Response codes
    {{ macros.generate_table('MTP_RESPONSE', tables['ResponseCode']) }}

-- Response parameter descriptions
    {{ macros.generate_parameters('MTP_RESPONSE_PARAMETERS', tables['Responses']) }}

-- Event names and types
    {{ macros.generate_table('MTP_EVENT', tables['EventCode']) }}

-- Device Properties
    {{ macros.generate_table('MTP_DEVICE_PROP', tables['DevicePropertyCode']) }}

-- Object Properties
    {{ macros.generate_table('MTP_OBJECT_PROP', tables['ObjectPropertyCode']) }}

-- various descriptions
    {{ macros.generate_table('MTP_FORM_FLAG', tables['Formflags']) }}
    {{ macros.generate_table('MTP_FORMAT', tables['FormatCode']) }}

local mtp_lookup = {
    -- ['OperationCodes'] = MTP_OPERATIONS,
    ['OperationCodeDescriptions'] = MTP_OPERATION_DESCRIPTIONS,
    ['ResponseCodeDescriptions'] = MTP_RESPONSE_DESCRIPTIONS,
    ['RequestParameters'] = MTP_REQUEST_PARAMETERS,
    ['ResponseParameters'] = MTP_RESPONSE_PARAMETERS,
    ['EventCodeDescriptions'] = MTP_EVENT_DESCRIPTIONS,
    ['DevicePropCode'] = MTP_DEVICE_PROP_DESCRIPTIONS,
    ['ObjectPropCode'] = MTP_OBJECT_PROP_DESCRIPTIONS,
    ['FormFlag'] = MTP_FORM_FLAG_DESCRIPTIONS,
    ['ObjectFormatCode'] = MTP_FORMAT_DESCRIPTIONS,
}

--------------------------------------------------
-- vendor specific ptp extensions. They are potentially based on JSON extracted from [4]

    {{ macros.generate_vendor_extensions( tables['extensions']) }}

-- Header fields used in the plugin:
-- Note: needs to be placed in front of the dissectors
local hdr_fields =
{
	-- length = ProtoField.uint32("ptp.length","Length"),
	-- packet_type = ProtoField.uint32("ptp.pktType","Packet Type",base.HEX),

	-- PTP layer
    -- Original comment: leaving names with "ptpip" to try and prevent namespace issues. probably changing later.
    transaction_id = ProtoField.uint32("ptp.transactionID","Transaction ID",base.HEX),
    opcode = ProtoField.uint16("ptp.opcode","Operation Code",base.HEX), --  BASE_HEX|BASE_EXT_STRING--
    response_code =  ProtoField.uint16("ptp.respcode","Response Code",base.HEX),
    vendor_response_code =  ProtoField.uint16("ptp.respcode","Response Code",base.HEX),
    event_code =  ProtoField.uint16("ptp.eventcode","Event Code",base.HEX),
    total_data_length = ProtoField.uint64("ptp.datalen", "Total Data Length",base.HEX),
    session_id = ProtoField.uint32("ptp.op.sessionid", "Session ID", base.HEX),
    param1 = ProtoField.uint32("ptp.param1", "Parameter 1", base.HEX),
    param2 = ProtoField.uint32("ptp.param2", "Parameter 2", base.HEX),
    param3 = ProtoField.uint32("ptp.param3", "Parameter 3", base.HEX),
    param4 = ProtoField.uint32("ptp.param4", "Parameter 4", base.HEX),
    param5 = ProtoField.uint32("ptp.param5", "Parameter 5", base.HEX),
    data = ProtoField.bytes("ptp.data", "Data", base.HEX),
}

-- Wireshark parser implementation
ptp_proto = Proto("PTP-Payload","Picture Transfer Protocol (Payload only)")

-- add the field to the protocol
ptp_proto.fields = hdr_fields

-- import fields from the parent pre- dissector
parent_length_field = Field.new("ptp.length")
parent_packet_type_field = Field.new("ptp.pktType")
parent_header_offset_field = Field.new("ptp.headerTidOffset") -- protocol specific offset to the tid from the PTP/IP or PTP dissector
parent_code_field = Field.new("ptp.pktCode") -- op / event / response code

-- our dissector is added down

-- current lookup tables
mtp_lookup_tables = mtp_lookup  -- dynamic combination mtp + camera-vendor
mtp_transaction_opcodes = {}    -- lookup table transactionID -> request.opcode (allows response parameter parsing)
mtp_transaction_opdescriptions = {} -- lookup table transactionID -> request description ('GetDeviceProperty: Exposure')

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
    camera_vendor = VENDORS.UNKNOWN
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

----------------------------------------
-- individual packet parsers:

--[[
 * Dissects the Operation Request Packet specified in [1] Section 2.3.6

 	Format according to [5] in plain PTP would be

 	9.3.2 Operation Request Phase
	Field  Data Type
	OperationCode    UINT16
	SessionID        UINT32
	TransactionID    UINT32 <--- tvb starts here
	Parameter[n]     Any [4 bytes]

	with n = 0..5

--]]

function dissect_operation_request(tvb, pinfo, tree, length)
    -- local opcode = tvb(0,2):le_uint()

    local code = parent_code_field()()
	local proto_title = 'MTP Operation'
	local opcode_desc = mtp_lookup_tables['OperationCodeDescriptions'][code]

	if opcode_desc then proto_title = 'MTP: ' .. opcode_desc end

	local subtree = tree:add(ptp_proto,tvb(), proto_title )
	if not opcode_desc then
        dprint( 'Unknown opcode' .. code )
        opcode_desc = 'Unknown'
    end

    local label =  'OpCode: ' .. string.format( '0x%04X (', code ) .. opcode_desc .. ')'
    subtree:add( hdr_fields.opcode, code, label)

    -- insert the transaction type in the lookup table
    local transaction_id = tvb(0,4):le_uint()
    mtp_transaction_opcodes[transaction_id] = code
    mtp_transaction_opdescriptions[transaction_id] = opcode_desc
    add_transaction_description(tvb, subtree)

    -- parameters:
    local parameter_names = mtp_lookup_tables['RequestParameters'][code]
	local param_type_name = add_parameter_description(tvb, pinfo, subtree, length, parameter_names)
    if param_type_name then mtp_transaction_opdescriptions[transaction_id] = opcode_desc .. ' : ' .. param_type_name end
end

--[[
 * Dissects the Operation Response Packet specified in [1] Section 2.3.7

 	Format according to [5] in plain PTP would be

 	9.3.5 Operation Request Phase
	Field  Data Type
	ResponseCode     UINT16
	SessionID        UINT32
	TransactionID    UINT32 <-- here our tvb starts
	Parameter[n]     Any [4 bytes]
	with n = 0..5

--]]

function dissect_operation_response(tvb, pinfo, tree, length)
    -- local code_tvb = tvb(0,2)
    -- local code = code_tvb:le_uint()
    local code = parent_code_field()()
    local code_desc = mtp_lookup_tables['ResponseCodeDescriptions'][code]

	local response_header = code_desc
	if not response_header then response_header = string.format( '0x%04x', code ) end

	local subtree = tree:add( ptp_proto, tvb(), "MTP Response: " .. response_header )

	if code_desc then
		subtree:add( hdr_fields.response_code, code, "Code: " .. code_desc .. string.format( ' (0x%04x)', code ) )
	else
		dprint( 'Unknown opcode' .. code )
		subtree:add(hdr_fields.response_code, code)
	end

    add_transaction_description(tvb, subtree)

    local parameter_names = mtp_lookup_tables['RequestParameters'][code]
    add_parameter_description(tvb,pinfo,subtree, length, parameter_names)
end

function dissect_event(tvb, pinfo, tree, length)
    local code = parent_code_field()()
    local code_desc = mtp_lookup_tables['EventCodeDescriptions'][code]

	local response_header = code_desc
	if not response_header then response_header = string.format( '0x%04x', code ) end

	local subtree = tree:add( ptp_proto, tvb(), "MTP Event: " .. response_header )

	if code_desc then
		subtree:add( hdr_fields.event_code, code, "Code: " .. code_desc .. string.format( ' (0x%04x)', code ) )
	else
		dprint( 'Unknown opcode' .. code )
		subtree:add(hdr_fields.event_code, code)
	end

    local transaction_id = tvb(0,4):le_uint()
    mtp_transaction_opcodes[transaction_id] = code
    mtp_transaction_opdescriptions[transaction_id] = code_desc
    add_transaction_description(tvb, subtree)

    local parameter_names -- = mtp_lookup_tables['EventParameters'][code]
    add_parameter_description(tvb,pinfo,subtree, length, parameter_names)
end

function dissect_none(tvb, pinfo, tree, length)
    local subtree = tree:add( ptp_proto, tvb(), "MTP Packet: "  )
    add_transaction_description(tvb, subtree)
end

function dissect_start_data(tvb, pinfo, tree, length)
    dissect_none(tvb,pinfo, tree, length)
end

function dissect_end_data(tvb, pinfo, tree, length)

    local data_tvb = tvb( 4 )
    local data_description

    -- redundant description as convenience, it helps reading lengthy get/set property logs
    local transaction_id = tvb(0,4):le_uint()
    local data_description = mtp_transaction_opdescriptions[transaction_id] or ''
    if data_tvb:len() <= 8 then data_description = data_description .. '=> ' .. tostring( data_tvb ) end

    local subtree = tree:add( ptp_proto, tvb(), "Data Packet: " .. data_description  )
    add_transaction_description(tvb, subtree)

    subtree:add( hdr_fields.data, tvb( 4 ) )
end

-- Only the following packet types are part of MTP
local MTP_DISSECTORS = {
    [PTPIP_PACKETTYPE.CMD_REQUEST]=      dissect_operation_request,
    [PTPIP_PACKETTYPE.CMD_RESPONSE]=     dissect_operation_response,
    [PTPIP_PACKETTYPE.EVENT]=            dissect_event,
    [PTPIP_PACKETTYPE.START_DATA_PACKET]=dissect_start_data,
    [PTPIP_PACKETTYPE.DATA_PACKET]=     dissect_none,
    [PTPIP_PACKETTYPE.CANCEL_TRANSACTION]= dissect_none,
    [PTPIP_PACKETTYPE.END_DATA_PACKET]=  dissect_end_data,
}

----------------------------------------


-- create a function to dissect packets

function ptp_proto.dissector(tvb,pinfo,tree)

   local packet_type = PTPIP_PACKETTYPE.UNDEFINED 
   local ptp_length = nil 
   local offset = nil
   
   if parent_packet_type_field() then packet_type = parent_packet_type_field()() end
   if parent_length_field() then ptp_length = parent_length_field()() end
   if parent_header_offset_field() then offset = parent_header_offset_field()() end

   if not offset or not ptp_length or packet_type == PTPIP_PACKETTYPE.UNDEFINED  then
   		dprint( 'Missing field in dissection' )
   		return
   end
   dprint( "Found packet:" .. packet_type .. ' l:' .. ptp_length .. ' o:' .. offset .. ' r:' .. ptp_length - offset)

   if offset > ptp_length then
   		dprint( 'PTP data size problem' )
   		return
   end

   local ptp_tvb =  tvb(offset)
   local remaining_length = ptp_length - offset

   local handler = MTP_DISSECTORS[packet_type]
   if handler then handler(  ptp_tvb, pinfo, tree, remaining_length ) end
end


mtp_table = DissectorTable.new("ptp.data", "MTP Protocol", ftypes.STRING )
-- register our protocol
mtp_table:add('ptp',ptp_proto)

function add_transaction_description(tvb, subtree)
    local sub_tvb = tvb(0,4)
    local transaction_id = sub_tvb:le_uint()
    local transaction_desc = mtp_transaction_opdescriptions[transaction_id]
    if transaction_desc then
        subtree:add(hdr_fields.transaction_id, sub_tvb, transaction_id, string.format( 'TransactionID: 0x%04X (', transaction_id ) .. transaction_desc .. ')' )
    else
	    subtree:add_le(hdr_fields.transaction_id, sub_tvb)
    end
end

local param_fields = {
	[0] = hdr_fields.param1,
	[1] = hdr_fields.param2,
	[2] = hdr_fields.param3,
	[3] = hdr_fields.param4,
	[4] = hdr_fields.param5,
}

function add_parameter_description(tvb,pinfo,tree, length, parameter_names)
    local start_offset = 4
	local remainder = length - start_offset
	local parameter_count = remainder / 4
    local parameter_name
    local command_description -- return description of PropCode types
	-- dprint2( parameter_count .. " Parameters" )
	if parameter_count >  0 then
		parameter_count = math.min(parameter_count, 5)
		for i = 0, parameter_count - 1 do
            local param_tvb =  tvb(start_offset + (4 * i), 4)
            local param_value = param_tvb:le_uint()

            if parameter_names then parameter_name = parameter_names[i + 1] end
            if parameter_name then
                parameter_name = parameter_name:gsub('%[','')
                parameter_name = parameter_name:gsub('%]','')

                local param_description_table = mtp_lookup_tables[parameter_name]
                local param_description
                if param_description_table then
                    param_description = param_description_table[param_value]
                end
                local label =  parameter_name .. ': ' .. string.format( '0x%04X ', param_value )
                if param_description then
                    label = label .. '(' .. param_description ..')'
                end

                -- determine if any propcode is in the parameter name - we use these parameters also for describing the transactionID
                if parameter_name and string.find( parameter_name, 'PropCode') then
                    if param_description then
                        command_description = param_description
                    else
                        command_description = string.format( '0x%04X ', param_value )
                    end
                end

                tree:add( param_fields[i], param_tvb, param_value, label )
            else
			    tree:add_le( param_fields[i], param_tvb )
            end

		end
    end
    return command_description
end

--------------------------------------------------------------------------------
-- preferences handling stuff
--------------------------------------------------------------------------------

function combine_lookup(table1, table2)
    -- iterate all keys in
    local result = {}
    local key, value, k, v

    for key, value in pairs(table1) do
        if table2[key] then
            local combined = {}
            for k,v in pairs(table1[key]) do combined[k] = v end
            for k,v in pairs(table2[key]) do combined[k] = v end
            result[key] = combined
        else
            result[key] = table1[key]
        end
    end
    return result
end

local debug_pref_enum = {
    { 1,  "Disabled", debug_level.DISABLED },
    { 2,  "Level 1",  debug_level.LEVEL_1  },
    { 3,  "Level 2",  debug_level.LEVEL_2  },
}


----------------------------------------
-- register our preferences

ptp_proto.prefs.debug       = Pref.enum("Debug", default_settings.debug_level,
                                        "The debug printing level", debug_pref_enum)
ptp_proto.prefs.vendor      = Pref.enum("Camera vendor", default_settings.camera_vendor, "Properly translates vendor specific opcodes", vendor_pref_enum)

----------------------------------------
-- the function for handling preferences being changed
function ptp_proto.prefs_changed()
    dprint2("prefs_changed called")

	default_settings.camera_vendor = ptp_proto.prefs.vendor
    default_settings.debug_level = ptp_proto.prefs.debug
    resetDebugLevel()

    mtp_lookup_tables = combine_lookup( mtp_lookup, VENDOR_EXTENSIONS[default_settings.camera_vendor] )
end